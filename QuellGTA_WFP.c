// 渟雲. Released to Public Domain.
//
// -----------------------------------------------------------------------------
// File: QuellGTA_WFP.c
// Author: 渟雲(quq[at]outlook.it)
// Date: 2025-12-5
//
// -----------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <fwpmu.h>
#include <fwptypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "rpcrt4.lib")

#define MAX_PATH_LENGTH 1024
#define TRANSACTION_TIMEOUT 5000

static const GUID kFirewallProviderGuid = {
    0x4310d91e,
    0xf336,
    0x43f3,
    {0xa2, 0x10, 0x88, 0x68, 0x48, 0xef, 0xc1, 0x4a}};

static const GUID kFirewallSublayerGuid = {
    0x9946b99e,
    0x15fb,
    0x4371,
    {0x9c, 0xa3, 0x84, 0xbe, 0x8b, 0x9b, 0x42, 0xad}};

typedef struct {
  char process_path[MAX_PATH_LENGTH];
  BOOL has_process;
} ConditionParams;

typedef enum {
  MODE_NONE = 0,
  MODE_CONDITIONAL,
  MODE_GLOBAL,
  MODE_CLEANUP
} OperationMode;

void PrintUsage(const char* program_name);
BOOL ParseArguments(int argc, char* argv[], OperationMode* mode,
                    ConditionParams* params);
BOOL InitializeWinsock();
BOOL RunAsAdministrator();
HANDLE OpenWfpEngine();
BOOL InitializeProvider(HANDLE engine_handle);
BOOL CleanupRules(HANDLE engine_handle);
BOOL CreateGlobalBlockRule(HANDLE engine_handle);
BOOL CreateConditionalRule(HANDLE engine_handle, const ConditionParams* params);
void CloseWfpEngine(HANDLE engine_handle);
BOOL StartTransaction(HANDLE engine_handle);
BOOL CommitTransaction(HANDLE engine_handle);
BOOL AbortTransaction(HANDLE engine_handle);

int main(int argc, char* argv[]) {
  SetConsoleOutputCP(CP_UTF8);
  OperationMode mode = MODE_NONE;
  ConditionParams params = {0};
  HANDLE engine_handle = NULL;
  BOOL success = FALSE;

  if (!RunAsAdministrator()) {
    return 1;
  }

  if (!ParseArguments(argc, argv, &mode, &params)) {
    PrintUsage(argv[0]);
    return 1;
  }

  if (!InitializeWinsock()) {
    return 1;
  }

  engine_handle = OpenWfpEngine();
  if (engine_handle == NULL) {
    WSACleanup();
    return 1;
  }

  switch (mode) {
    case MODE_CONDITIONAL:
      if (!InitializeProvider(engine_handle)) {
        break;
      }
      success = CreateConditionalRule(engine_handle, &params);
      break;

    case MODE_GLOBAL:
      if (!InitializeProvider(engine_handle)) {
        break;
      }
      success = CreateGlobalBlockRule(engine_handle);
      break;

    case MODE_CLEANUP:
      success = CleanupRules(engine_handle);
      break;

    default:
      PrintUsage(argv[0]);
      success = FALSE;
      break;
  }

  CloseWfpEngine(engine_handle);
  WSACleanup();

  if (success) {
    return 0;
  } else {
    return 1;
  }
}

void PrintUsage(const char* program_name) {
  printf("%s -c [-p 进程路径]\n", program_name);
  printf("%s -g\n", program_name);
  printf("%s -d\n", program_name);
}

BOOL ParseArguments(int argc, char* argv[], OperationMode* mode,
                    ConditionParams* params) {
  if (argc < 2) {
    return FALSE;
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--conditional") == 0) {
      *mode = MODE_CONDITIONAL;
    } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--global") == 0) {
      *mode = MODE_GLOBAL;
    } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--delete") == 0) {
      *mode = MODE_CLEANUP;
    } else if (strcmp(argv[i], "-p") == 0 ||
               strcmp(argv[i], "--process") == 0) {
      if (i + 1 < argc) {
        strncpy_s(params->process_path, MAX_PATH_LENGTH, argv[i + 1],
                  _TRUNCATE);
        params->has_process = TRUE;
        i++;
      } else {
        return FALSE;
      }
    } else {
      return FALSE;
    }
  }

  if (*mode == MODE_CONDITIONAL) {
    if (!params->has_process) {
      return FALSE;
    }
  } else if (*mode == MODE_NONE) {
    return FALSE;
  }

  return TRUE;
}

BOOL InitializeWinsock() {
  WSADATA wsa_data;
  return (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0);
}

BOOL RunAsAdministrator() {
  BOOL is_admin = FALSE;
  PSID administrators_group = NULL;
  SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;

  if (AllocateAndInitializeSid(&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                               DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
                               &administrators_group)) {
    if (!CheckTokenMembership(NULL, administrators_group, &is_admin)) {
      is_admin = FALSE;
    }
    FreeSid(administrators_group);
  }

  return is_admin;
}

HANDLE OpenWfpEngine() {
  HANDLE engine_handle = NULL;
  FWPM_SESSION0 session = {0};
  DWORD status;

  session.displayData.name = L"FirewallCLI";
  session.displayData.description = L"Command Line Firewall Tool";
  session.flags = 0;
  session.txnWaitTimeoutInMSec = TRANSACTION_TIMEOUT;

  status =
      FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine_handle);

  if (status != ERROR_SUCCESS) {
    return NULL;
  }

  return engine_handle;
}

BOOL InitializeProvider(HANDLE engine_handle) {
  FWPM_PROVIDER0 provider = {0};
  FWPM_SUBLAYER0 sublayer = {0};
  DWORD status;

  FWPM_PROVIDER0* existing_provider = NULL;
  status = FwpmProviderGetByKey0(engine_handle, &kFirewallProviderGuid,
                                 &existing_provider);

  if (status == ERROR_SUCCESS && existing_provider != NULL) {
    FwpmFreeMemory0((void**)&existing_provider);
    return TRUE;
  }

  provider.displayData.name = L"FirewallCLI Provider";
  provider.displayData.description = L"Provider for Firewall Command Line Tool";
  provider.providerKey = kFirewallProviderGuid;
  provider.flags = 0;

  status = FwpmProviderAdd0(engine_handle, &provider, NULL);
  if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
    return FALSE;
  }

  sublayer.displayData.name = L"FirewallCLI Sublayer";
  sublayer.displayData.description = L"Sublayer for Firewall Command Line Tool";
  sublayer.providerKey = &kFirewallProviderGuid;
  sublayer.subLayerKey = kFirewallSublayerGuid;
  sublayer.weight = 0xFFFF;

  status = FwpmSubLayerAdd0(engine_handle, &sublayer, NULL);
  if (status != ERROR_SUCCESS && status != FWP_E_ALREADY_EXISTS) {
    return FALSE;
  }

  return TRUE;
}

BOOL CleanupRules(HANDLE engine_handle) {
  DWORD status;
  BOOL in_transaction = FALSE;

  if (StartTransaction(engine_handle)) {
    in_transaction = TRUE;
  }

  HANDLE enum_handle = NULL;
  FWPM_FILTER0** filters = NULL;
  UINT32 num_filters = 0;

  status = FwpmFilterCreateEnumHandle0(engine_handle, NULL, &enum_handle);
  if (status == ERROR_SUCCESS) {
    status = FwpmFilterEnum0(engine_handle, enum_handle, 1000, &filters,
                             &num_filters);
    if (status == ERROR_SUCCESS && filters != NULL) {
      for (UINT32 i = 0; i < num_filters; i++) {
        if (filters[i] && filters[i]->providerKey &&
            IsEqualGUID(filters[i]->providerKey, &kFirewallProviderGuid)) {
          status =
              FwpmFilterDeleteByKey0(engine_handle, &filters[i]->filterKey);
        }
      }
      FwpmFreeMemory0((void**)&filters);
    }

    if (enum_handle) {
      FwpmFilterDestroyEnumHandle0(engine_handle, enum_handle);
    }
  }

  status = FwpmSubLayerDeleteByKey0(engine_handle, &kFirewallSublayerGuid);
  status = FwpmProviderDeleteByKey0(engine_handle, &kFirewallProviderGuid);

  if (in_transaction) {
    if (!CommitTransaction(engine_handle)) {
      AbortTransaction(engine_handle);
      return FALSE;
    }
  }

  return TRUE;
}

BOOL StartTransaction(HANDLE engine_handle) {
  DWORD status = FwpmTransactionBegin0(engine_handle, 0);
  if (status != ERROR_SUCCESS && status != FWP_E_TXN_IN_PROGRESS) {
    return FALSE;
  }
  return (status == ERROR_SUCCESS);
}

BOOL CommitTransaction(HANDLE engine_handle) {
  DWORD status = FwpmTransactionCommit0(engine_handle);
  if (status != ERROR_SUCCESS) {
    return FALSE;
  }
  return TRUE;
}

BOOL AbortTransaction(HANDLE engine_handle) {
  FwpmTransactionAbort0(engine_handle);
  return TRUE;
}

BOOL CreateGlobalBlockRule(HANDLE engine_handle) {
  FWPM_FILTER0 filter = {0};
  DWORD status;
  BOOL in_transaction = FALSE;

  GUID filter_guid;
  UuidCreate(&filter_guid);

  if (StartTransaction(engine_handle)) {
    in_transaction = TRUE;
  }

  filter.filterKey = filter_guid;
  filter.displayData.name = L"Global Block Rule";
  filter.displayData.description = L"Block all outbound IPv4 connections";

  filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  filter.subLayerKey = kFirewallSublayerGuid;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = 0xF;

  filter.numFilterConditions = 0;
  filter.filterCondition = NULL;

  filter.action.type = FWP_ACTION_BLOCK;

  filter.providerKey = (GUID*)&kFirewallProviderGuid;
  filter.flags = FWPM_FILTER_FLAG_INDEXED | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

  UINT64 filter_id;
  status = FwpmFilterAdd0(engine_handle, &filter, NULL, &filter_id);

  if (status != ERROR_SUCCESS) {
    if (in_transaction) {
      AbortTransaction(engine_handle);
    }
    return FALSE;
  }

  if (in_transaction) {
    if (!CommitTransaction(engine_handle)) {
      return FALSE;
    }
  }

  return TRUE;
}

BOOL CreateConditionalRule(HANDLE engine_handle,
                           const ConditionParams* params) {
  FWPM_FILTER0 filter = {0};
  FWPM_FILTER_CONDITION condition = {0};
  DWORD status = 0;
  FWP_BYTE_BLOB* app_blob = NULL;

  if (!params->has_process) {
    return FALSE;
  }

  filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

  WCHAR wide_path[MAX_PATH_LENGTH];
  if (MultiByteToWideChar(CP_UTF8, 0, params->process_path, -1, wide_path,
                          MAX_PATH_LENGTH) == 0) {
    return FALSE;
  }
  status = FwpmGetAppIdFromFileName0(wide_path, &app_blob);
  if (status != ERROR_SUCCESS || app_blob == NULL) {
    return FALSE;
  }

  condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
  condition.matchType = FWP_MATCH_EQUAL;
  condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
  condition.conditionValue.byteBlob = app_blob;

  UuidCreate(&filter.filterKey);
  filter.displayData.name = L"Conditional Block Rule";
  filter.displayData.description =
      L"Conditional block outbound IPv4 connections";
  filter.subLayerKey = kFirewallSublayerGuid;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = 0xF;

  filter.numFilterConditions = 1;
  filter.filterCondition = &condition;

  filter.action.type = FWP_ACTION_BLOCK;
  filter.providerKey = (GUID*)&kFirewallProviderGuid;
  filter.flags = FWPM_FILTER_FLAG_INDEXED | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;

  UINT64 filter_id = 0;
  status = FwpmFilterAdd0(engine_handle, &filter, NULL, &filter_id);

  if (app_blob) FwpmFreeMemory0((void**)&app_blob);

  if (status != ERROR_SUCCESS) {
    return FALSE;
  }

  return TRUE;
}

void CloseWfpEngine(HANDLE engine_handle) {
  if (engine_handle != NULL) {
    FwpmEngineClose0(engine_handle);
  }
}
