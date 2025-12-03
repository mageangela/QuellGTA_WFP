// 渟雲. Released to Public Domain.
//
// -----------------------------------------------------------------------------
// File: QuellGTA_WFP.h
// Author: 渟雲(quq[at]outlook.it)
// Date: 2025-12-3
//
// -----------------------------------------------------------------------------
#pragma once
#ifndef QUELLGTA_WFP_H
#define QUELLGTA_WFP_H
#include <windows.h>
#include <fwpmu.h>
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
namespace build {
static wchar_t kCustomFilterName[] = L"QuellGTA_Block";
static wchar_t kGlobalFilterName[] = L"QuellGTA_Global_Block";
static wchar_t kCustomFilterDescription[] =
    L"Blocks network traffic for QuellGTA";
static wchar_t kGlobalFilterDescription[] =
    L"Globally blocks all network traffic";
static wchar_t kUniqueProviderDescription[] = L"QuellGTA Firewall Provider";
static wchar_t kFilterProviderName[] = L"QuellGTAFirewallProvider";
}  // namespace build

BOOL IsProcessHighIntegrity();
BOOL FindProviderGuidByDesc(HANDLE wfp_session, PCWSTR provider_desc,
                            GUID* provider_guid);
BOOL CustomFwpmGetAppIdFromFileName(PCWSTR file_name, FWP_BYTE_BLOB** app_id);
BOOL BlockTraffic(LPWSTR process_name, LPWSTR full_path, LPCWSTR ipAddr,
                  UINT16 port);
BOOL UnblockTraffic();
#endif
