// 渟雲. Released to Public Domain.
//
// -----------------------------------------------------------------------------
// File: QuellGTA_WFP.cc
// Author: 渟雲(quq[at]outlook.it)
// Date: 2025-12-3
//
// -----------------------------------------------------------------------------
#include "QuellGTA_WFP.h"
#include <Psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <vector>
#include <locale.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Ws2_32.lib")

// 检查管理员权限
BOOL IsProcessHighIntegrity() {
  BOOL state = FALSE;
  HANDLE token = NULL;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
    return FALSE;
  }

  DWORD label_size = 0;
  if (!GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &label_size) &&
      GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    CloseHandle(token);
    return FALSE;
  }

  PTOKEN_MANDATORY_LABEL token_label =
      (PTOKEN_MANDATORY_LABEL)malloc(label_size);
  if (!token_label) {
    CloseHandle(token);
    return FALSE;
  }

  if (GetTokenInformation(token, TokenIntegrityLevel, token_label, label_size,
                          &label_size)) {
    DWORD sub_auth_count = *GetSidSubAuthorityCount(token_label->Label.Sid);
    DWORD sub_auth =
        *GetSidSubAuthority(token_label->Label.Sid, sub_auth_count - 1);

    state = (sub_auth >= SECURITY_MANDATORY_HIGH_RID);
  }

  free(token_label);
  CloseHandle(token);

  return state;
}

// Find provider GUID by description
BOOL FindProviderGuidByDesc(HANDLE wfp_session, PCWSTR provider_desc,
                            GUID* provider_guid) {
  BOOL state = TRUE;
  DWORD status = 0;
  HANDLE wfp_enum = NULL;
  FWPM_PROVIDER0** provider_list = NULL;
  UINT32 provider_count = 0;
  BOOL found_match = FALSE;

  status = FwpmProviderCreateEnumHandle0(wfp_session, NULL, &wfp_enum);
  if (status != ERROR_SUCCESS) {
    state = FALSE;
    goto cleanup;
  }

  status = FwpmProviderEnum0(wfp_session, wfp_enum, 100, &provider_list,
                             &provider_count);
  if (status != ERROR_SUCCESS) {
    state = FALSE;
    goto cleanup;
  }

  for (UINT32 idx = 0; idx < provider_count; idx++) {
    if (provider_list[idx]->displayData.description != NULL) {
      if (wcscmp(provider_list[idx]->displayData.description, provider_desc) ==
          0) {
        *provider_guid = provider_list[idx]->providerKey;
        found_match = TRUE;
        break;
      }
    }
  }

  if (!found_match) {
    state = FALSE;
  }

cleanup:
  if (provider_list) {
    FwpmFreeMemory0((void**)&provider_list);
  }
  if (wfp_enum) {
    FwpmProviderDestroyEnumHandle0(wfp_session, wfp_enum);
  }

  return state;
}

BOOL CustomFwpmGetAppIdFromFileName(PCWSTR file_name, FWP_BYTE_BLOB** app_id) {
  BOOL state = TRUE;
  SIZE_T path_size = 0;
  HANDLE heap = NULL;

  if (!file_name) {
    state = FALSE;
    goto cleanup;
  }

  heap = GetProcessHeap();
  *app_id =
      (FWP_BYTE_BLOB*)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(FWP_BYTE_BLOB));
  if (!*app_id) {
    state = FALSE;
    goto cleanup;
  }

  path_size = (wcslen(file_name) + 1) * sizeof(WCHAR);
  (*app_id)->size = (UINT32)path_size;
  (*app_id)->data = (UINT8*)HeapAlloc(heap, HEAP_ZERO_MEMORY, path_size);
  if (!(*app_id)->data) {
    state = FALSE;
    goto cleanup;
  }

  memcpy((*app_id)->data, file_name, path_size);

cleanup:
  if (state == FALSE) {
    if (*app_id) {
      if ((*app_id)->data) {
        HeapFree(heap, 0, (*app_id)->data);
      }
      HeapFree(heap, 0, *app_id);
      *app_id = NULL;
    }
  }

  return state;
}

BOOL BlockTraffic(LPWSTR process_name, LPWSTR full_path, LPCWSTR ipAddr,
                  UINT16 port) {
  BOOL state = TRUE;
  DWORD status = 0;
  HANDLE wfp_session = NULL;
  HANDLE process_heap = NULL;

  FWP_BYTE_BLOB* app_id_blob = NULL;
  UINT64 filter_id = 0;

  process_heap = GetProcessHeap();

  FWPM_FILTER0 filter_details = {0};
  FWPM_FILTER_CONDITION0 filter_conditions[3] = {0};
  int condition_count = 0;

  GUID provider_guid = {0};
  FWPM_PROVIDER0 filter_provider = {0};

  status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &wfp_session);
  if (status != ERROR_SUCCESS) {
    state = FALSE;
    goto cleanup;
  }

  if (full_path && wcslen(full_path) > 0) {
    if (!NT_SUCCESS(FwpmGetAppIdFromFileName0(full_path, &app_id_blob))) {
      DWORD dwError = GetLastError();  // <-- 获取系统错误码
      std::wcerr << L"错误: FwpmGetAppIdFromFileName0 失败。错误代码: "
                 << dwError << std::endl;
      state = FALSE;
      goto cleanup;
    }
    std::wcout << L"App ID 信息:" << std::endl;
    std::wcout << L"  大小: " << app_id_blob->size << L" 字节" << std::endl;
    std::wcout << L"  内容(前100字节): ";
    for (UINT32 i = 0; i < min(app_id_blob->size, 100); i++) {
      wprintf(L"%02X ", app_id_blob->data[i]);
    }
    std::wcout << std::endl;
    std::wcout << L"  路径字符串: ";
    wprintf(L"%ls\n", (wchar_t*)app_id_blob->data);
    std::wcout << L"为进程创建规则: " << full_path << std::endl;
    std::wcout << L"App ID大小: " << app_id_blob->size << L" 字节" << std::endl;
  } else {
    std::wcout << L"创建全局阻断规则" << std::endl;
  }

  if (FindProviderGuidByDesc(wfp_session, build::kUniqueProviderDescription,
                             &provider_guid)) {
    // 提供商已存在
  } else {
    filter_provider.displayData.name = build::kFilterProviderName;
    filter_provider.displayData.description = build::kUniqueProviderDescription;
    filter_provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

    status = FwpmProviderAdd0(wfp_session, &filter_provider, NULL);
    if (status != ERROR_SUCCESS) {
      std::wcerr << L"创建提供商失败: " << status << std::endl;
      state = FALSE;
      goto cleanup;
    }

    if (!FindProviderGuidByDesc(wfp_session, build::kUniqueProviderDescription,
                                &provider_guid)) {
      state = FALSE;
      goto cleanup;
    }
  }


  // 设置进程条件
  if (app_id_blob) {
    filter_conditions[condition_count].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    filter_conditions[condition_count].matchType = FWP_MATCH_EQUAL;
    filter_conditions[condition_count].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    filter_conditions[condition_count].conditionValue.byteBlob = app_id_blob;
    condition_count++;
  }

  // 设置IP条件（如果提供）
  if (ipAddr && wcslen(ipAddr) > 0) {
    char ipStr[64] = {0};
    WideCharToMultiByte(CP_ACP, 0, ipAddr, -1, ipStr, sizeof(ipStr), NULL,
                        NULL);

    unsigned long ip = inet_addr(ipStr);
    if (ip != INADDR_NONE) {
      filter_conditions[condition_count].fieldKey =
          FWPM_CONDITION_IP_REMOTE_ADDRESS;
      filter_conditions[condition_count].matchType = FWP_MATCH_EQUAL;
      filter_conditions[condition_count].conditionValue.type = FWP_UINT32;
      filter_conditions[condition_count].conditionValue.uint32 = ip;
      condition_count++;
    }
  }

  // 设置端口条件（如果提供）
  if (port > 0) {
    filter_conditions[condition_count].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    filter_conditions[condition_count].matchType = FWP_MATCH_EQUAL;
    filter_conditions[condition_count].conditionValue.type = FWP_UINT16;
    filter_conditions[condition_count].conditionValue.uint16 = port;
    condition_count++;
  }

  // 设置过滤器基本信息
  if (condition_count > 0) {
    filter_details.displayData.name = build::kCustomFilterName;
    filter_details.displayData.description = build::kCustomFilterDescription;
    filter_details.filterCondition = filter_conditions;
    filter_details.numFilterConditions = condition_count;
  } else {
    // 全局阻断
    filter_details.displayData.name = build::kGlobalFilterName;
    filter_details.displayData.description = build::kGlobalFilterDescription;
    filter_details.filterCondition = NULL;
    filter_details.numFilterConditions = 0;
  }

  filter_details.flags = FWPM_FILTER_FLAG_PERSISTENT;
  filter_details.action.type = FWP_ACTION_BLOCK;
  filter_details.providerKey = &provider_guid;

  // 层 1: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
  filter_details.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
  filter_id = 0;
  status = FwpmFilterAdd0(wfp_session, &filter_details, NULL, &filter_id);
  if (status != ERROR_SUCCESS) {
    std::wcerr << L"添加接收IPv4过滤器失败: " << status << std::endl;
    state = FALSE;
    goto cleanup;
  }
  std::wcout << L"接收IPv4过滤器ID: " << filter_id << std::endl;

  // 层 2: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
  filter_details.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
  filter_id = 0;
  status = FwpmFilterAdd0(wfp_session, &filter_details, NULL, &filter_id);
  if (status != ERROR_SUCCESS) {
    std::wcerr << L"添加接收IPv6过滤器失败: " << status << std::endl;
    state = FALSE;
    goto cleanup;
  }
  std::wcout << L"接收IPv6过滤器ID: " << filter_id << std::endl;

  // 层 3: FWPM_LAYER_ALE_AUTH_CONNECT_V4
  filter_details.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  filter_id = 0;
  status = FwpmFilterAdd0(wfp_session, &filter_details, NULL, &filter_id);
  if (status != ERROR_SUCCESS) {
    std::wcerr << L"添加连接IPv4过滤器失败: " << status << std::endl;
    state = FALSE;
    goto cleanup;
  }
  std::wcout << L"连接IPv4过滤器ID: " << filter_id << std::endl;

  // 层 4: FWPM_LAYER_ALE_AUTH_CONNECT_V6
  filter_details.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
  filter_id = 0;
  status = FwpmFilterAdd0(wfp_session, &filter_details, NULL, &filter_id);
  if (status != ERROR_SUCCESS) {
    std::wcerr << L"添加连接IPv6过滤器失败: " << status << std::endl;
    state = FALSE;
    goto cleanup;
  }
  std::wcout << L"连接IPv6过滤器ID: " << filter_id << std::endl;

cleanup:
  if (app_id_blob) {
    if (app_id_blob->data) HeapFree(process_heap, 0, app_id_blob->data);
    HeapFree(process_heap, 0, app_id_blob);
  }
  if (wfp_session) FwpmEngineClose0(wfp_session);

  return state;
}

// Delete all filters created by this tool
BOOL UnblockTraffic() {
  BOOL state = TRUE;
  DWORD status = 0;
  HANDLE wfp_session = NULL;
  HANDLE filter_enum = NULL;
  FWPM_FILTER0** filter_list = NULL;
  UINT32 filter_count = 0;
  BOOL filter_found = FALSE;

  // 要删除的过滤器名称列表
  PCWSTR filterNames[] = {build::kCustomFilterName, build::kGlobalFilterName};
  int filterNameCount = sizeof(filterNames) / sizeof(filterNames[0]);

  status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &wfp_session);
  if (status != ERROR_SUCCESS) {
    state = FALSE;
    goto cleanup;
  }

  status = FwpmFilterCreateEnumHandle0(wfp_session, NULL, &filter_enum);
  if (status != ERROR_SUCCESS) {
    state = FALSE;
    goto cleanup;
  }

  while (TRUE) {
    status = FwpmFilterEnum0(wfp_session, filter_enum, 1, &filter_list,
                             &filter_count);
    if (status != ERROR_SUCCESS || filter_count == 0) {
      break;
    }

    FWPM_DISPLAY_DATA0* display_data = &filter_list[0]->displayData;
    LPWSTR filter_name = display_data->name;

    // 检查是否是我们创建的过滤器
    BOOL isOurFilter = FALSE;
    for (int i = 0; i < filterNameCount; i++) {
      if (wcscmp(filter_name, filterNames[i]) == 0) {
        isOurFilter = TRUE;
        break;
      }
    }

    if (isOurFilter) {
      filter_found = TRUE;
      UINT64 filter_id = filter_list[0]->filterId;

      status = FwpmFilterDeleteById0(wfp_session, filter_id);
      if (status != ERROR_SUCCESS) {
        state = FALSE;
      }

      if (filter_list) {
        FwpmFreeMemory0((void**)&filter_list);
        filter_list = NULL;
      }
    }
  }

  if (!filter_found) {
    // 没有找到我们的过滤器，不算错误
    state = TRUE;
  }

cleanup:
  if (filter_enum) {
    FwpmFilterDestroyEnumHandle0(wfp_session, filter_enum);
  }

  if (wfp_session) {
    FwpmEngineClose0(wfp_session);
  }

  if (filter_list) {
    FwpmFreeMemory0((void**)&filter_list);
  }

  return state;
}

// 打印使用说明
void PrintUsage() {
  std::wcout << L"QuellGTA WFP 防火墙工具" << std::endl;
  std::wcout << std::endl;
  std::wcout << L"用法:" << std::endl;
  std::wcout << L"  QuellGTA_WFP.exe -f [进程路径] [IP地址] [端口]"
             << std::endl;
  std::wcout << L"      # 创建网络阻断规则" << std::endl;
  std::wcout << L"  QuellGTA_WFP.exe -r            # 解除所有网络阻断规则"
             << std::endl;
  std::wcout << std::endl;
  std::wcout << L"  QuellGTA_WFP.exe -h            # 显示此帮助信息"
             << std::endl;
  std::wcout << std::endl;
  std::wcout << L"注意:" << std::endl;
  std::wcout << L"  1. 需要以管理员权限运行" << std::endl;
  std::wcout << L"  2. 参数为空字符串时使用双引号表示\"\"" << std::endl;
}
// 主函数
int wmain(int argc, wchar_t* argv[]) {
  setlocale(LC_ALL,
            "chs");

  // 检查管理员权限
  if (!IsProcessHighIntegrity()) {
    std::wcerr << L"错误: 需要管理员权限" << std::endl;
    return 1;
  }

  if (argc < 2) {
    PrintUsage();
    return 1;
  }

  if (_wcsicmp(argv[1], L"-h") == 0 || _wcsicmp(argv[1], L"--help") == 0) {
    PrintUsage();
    return 0;
  }

  if (_wcsicmp(argv[1], L"-f") == 0) {
    LPWSTR processPath = NULL;
    LPCWSTR ipAddr = NULL;
    UINT16 port = 0;

    if (argc >= 3) processPath = argv[2];
    if (argc >= 4) ipAddr = argv[3];
    if (argc >= 5) port = (UINT16)_wtoi(argv[4]);

    std::wcout << L"正在阻断: ";
    if (processPath) std::wcout << L"进程=" << processPath << L" ";
    if (ipAddr) std::wcout << L"IP=" << ipAddr << L" ";
    if (port) std::wcout << L"端口=" << port << L" ";
    if (!processPath && !ipAddr && !port) std::wcout << L"全局阻断";
    std::wcout << std::endl;

    wchar_t processName[MAX_PATH] = {0};
    if (processPath) {
      _wsplitpath_s(processPath, NULL, 0, NULL, 0, processName, MAX_PATH, NULL,
                    0);
    }

    if (BlockTraffic(processName, processPath, ipAddr, port)) {
      std::wcout << L"成功设置阻断规则" << std::endl;
      return 0;
    } else {
      std::wcerr << L"阻断失败" << std::endl;
      return 1;
    }
  } else if (_wcsicmp(argv[1], L"-r") == 0) {
    std::wcout << L"正在解除所有网络阻断..." << std::endl;
    if (UnblockTraffic()) {
      std::wcout << L"成功解除所有网络阻断" << std::endl;
      return 0;
    } else {
      std::wcerr << L"解除阻断失败" << std::endl;
      return 1;
    }
  } else {
    std::wcerr << L"未知参数: " << argv[1] << std::endl;
    PrintUsage();
    return 1;
  }

  return 0;
}
