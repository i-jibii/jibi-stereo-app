#include "ext/imgui/imgui.h"
#include "ext/imgui/imgui_impl_win32.h"
#include "ext/imgui/imgui_impl_dx11.h"

#include "fonts/IconsFontAwesome6.h" 
#include <d3d11.h>
#include <tchar.h>
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <shlobj.h>
#include <wininet.h>
#include <shlwapi.h>
#include <versionhelpers.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS") 

// ============================================================================
// D3D11 Global State
// ============================================================================
static ID3D11Device* g_D3D11Device = nullptr;
static ID3D11DeviceContext* g_D3D11DeviceContext = nullptr;
static IDXGISwapChain* g_SwapChain = nullptr;
static ID3D11RenderTargetView* g_MainRenderTargetView = nullptr;
static UINT g_ResizeWidth = 0;
static UINT g_ResizeHeight = 0;
static bool g_SwapChainOccluded = false;

// ============================================================================
// Window Dragging State
// ============================================================================
static bool g_IsDragging = false;
static ImVec2 g_DragOffset(0, 0);

// ============================================================================
// Application Constants
// ============================================================================
constexpr int WINDOW_WIDTH = 530;
constexpr int WINDOW_HEIGHT = 295;
constexpr int WINDOW_CORNER_RADIUS = 20;
constexpr float BORDER_THICKNESS = 3.0f;
constexpr float BORDER_ROUNDING = 8.0f;

// ============================================================================
// Discord Voice Node Version
// ============================================================================
#define VERSION 9219

// ============================================================================
// RVA Offsets for Version 9219
// ============================================================================
uint32_t CreateAudioFrameStereoInstruction = 0x116C91;
uint32_t AudioEncoderOpusConfigSetChannelsInstruction = 0x3A0B64;
uint32_t MonoDownmixerInstructions = 0xD6319;
uint32_t HighPassFilter_Process = 0x52CF70;
uint32_t EmulateStereoSuccess1 = 0x520CFB;
uint32_t EmulateStereoSuccess2 = 0x520D07;
uint32_t EmulateBitrateModified = 0x52115A;
uint32_t Emulate48Khz = 0x520E63;
uint32_t HighpassCutoffFilter = 0x8D64B0;
uint32_t DcReject = 0x8D6690;
uint32_t downmix_func = 0x8D2820;
uint32_t AudioEncoderOpusConfig_IsOk = 0x3A0E00;
uint32_t SetsBitrate_BitrateValue = 0x522F81;
uint32_t SetsBitrate_BitwiseOr = 0x522F89;
uint32_t WebRtcOpus_SetBitrate_Check = 0x6A8FA5;
uint32_t ThrowError = 0x2B3340;

// ============================================================================
// Forward Declarations
// ============================================================================
bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ============================================================================
// Page Navigation
// ============================================================================
enum Page { PAGE_HOME, PAGE_SETTINGS, PAGE_TROUBLESHOOT };

// ============================================================================
// PE File Offset Calculation (RVA to File Offset)
// ============================================================================
uint32_t RvaToFileOffset(uint8_t* fileData, uint32_t rva)
{
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)fileData;
    IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)(fileData + dosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if (rva >= sectionHeader[i].VirtualAddress &&
            rva < sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize)
        {
            return rva - sectionHeader[i].VirtualAddress + sectionHeader[i].PointerToRawData;
        }
    }
    return rva;
}

// ============================================================================
// Generate Shellcode for hp_cutoff Function
// ============================================================================
std::vector<uint8_t> GenerateHpCutoffShellcode(int multiplier)
{
    uint8_t multiplierByte = (uint8_t)(multiplier & 0xFF);

    std::vector<uint8_t> shellcode;

    shellcode.insert(shellcode.end(), {
        0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
        0x53, 0x48, 0x83, 0xEC, 0x28, 0x49, 0x89, 0xCF, 0x41, 0x89, 0xD6,
        0x4D, 0x89, 0xC5, 0x4D, 0x89, 0xCC, 0x44, 0x8B, 0x5D, 0x30, 0x8B, 0x5D, 0x38,
        0x4D, 0x89, 0xE0, 0x49, 0x81, 0xE8, 0x84, 0x37, 0x00, 0x00,
        0x41, 0xB9, 0xEA, 0x03, 0x00, 0x00, 0x45, 0x89, 0x88, 0x94, 0x37, 0x00, 0x00,
        0x41, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0x45, 0x89, 0x88, 0xA0, 0x00, 0x00, 0x00,
        0x45, 0x89, 0x88, 0xA4, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC9,
        0x45, 0x89, 0x88, 0xB8, 0x00, 0x00, 0x00, 0x41, 0x0F, 0xAF, 0xDB,
        0x85, 0xDB, 0x0F, 0x8E
        });

    size_t jleOffsetPos = shellcode.size();
    shellcode.insert(shellcode.end(), { 0x00, 0x00, 0x00, 0x00 });

    shellcode.insert(shellcode.end(), { 0x8B, 0x45, 0x38 });

    if (multiplier >= 0) {
        shellcode.insert(shellcode.end(), { 0x83, 0xC0, multiplierByte });
    }
    else {
        uint8_t absMultiplier = (uint8_t)((-multiplier) & 0xFF);
        shellcode.insert(shellcode.end(), { 0x83, 0xE8, absMultiplier });
    }

    shellcode.insert(shellcode.end(), { 0xF3, 0x0F, 0x2A, 0xC8, 0x31, 0xC0 });

    size_t loopStart = shellcode.size();

    shellcode.insert(shellcode.end(), {
        0xF3, 0x41, 0x0F, 0x10, 0x04, 0x87, 0xF3, 0x0F, 0x59, 0xC1,
        0xF3, 0x41, 0x0F, 0x11, 0x44, 0x85, 0x00, 0x48, 0xFF, 0xC0,
        0x39, 0xD8, 0x7C
        });

    size_t currentPos = shellcode.size();
    int8_t jumpBack = (int8_t)(loopStart - currentPos - 1);
    shellcode.push_back((uint8_t)jumpBack);

    size_t endLoop = shellcode.size();

    int32_t jleOffset = (int32_t)(endLoop - jleOffsetPos - 4);
    shellcode[jleOffsetPos] = (uint8_t)(jleOffset & 0xFF);
    shellcode[jleOffsetPos + 1] = (uint8_t)((jleOffset >> 8) & 0xFF);
    shellcode[jleOffsetPos + 2] = (uint8_t)((jleOffset >> 16) & 0xFF);
    shellcode[jleOffsetPos + 3] = (uint8_t)((jleOffset >> 24) & 0xFF);

    shellcode.insert(shellcode.end(), {
        0x48, 0x83, 0xC4, 0x28, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3
        });

    while (shellcode.size() < 0x100)
        shellcode.push_back(0x90);

    return shellcode;
}

// ============================================================================
// Generate Shellcode for dc_reject Function
// ============================================================================
std::vector<uint8_t> GenerateDcRejectShellcode(int multiplier)
{
    uint8_t multiplierByte = (uint8_t)(multiplier & 0xFF);

    std::vector<uint8_t> shellcode;

    shellcode.insert(shellcode.end(), {
        0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54,
        0x53, 0x48, 0x83, 0xEC, 0x20, 0x49, 0x89, 0xCF, 0x49, 0x89, 0xD5,
        0x4D, 0x89, 0xC4, 0x45, 0x89, 0xCE, 0x8B, 0x5D, 0x30,
        0x4D, 0x89, 0xE0, 0x49, 0x81, 0xE8, 0x84, 0x37, 0x00, 0x00,
        0x41, 0xB9, 0xEA, 0x03, 0x00, 0x00, 0x45, 0x89, 0x88, 0x94, 0x37, 0x00, 0x00,
        0x41, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0x45, 0x89, 0x88, 0xA0, 0x00, 0x00, 0x00,
        0x45, 0x89, 0x88, 0xA4, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC9,
        0x45, 0x89, 0x88, 0xB8, 0x00, 0x00, 0x00, 0x44, 0x0F, 0xAF, 0xF3,
        0x45, 0x85, 0xF6, 0x0F, 0x8E
        });

    size_t jleOffsetPos = shellcode.size();
    shellcode.insert(shellcode.end(), { 0x00, 0x00, 0x00, 0x00 });

    shellcode.insert(shellcode.end(), { 0x8B, 0x45, 0x30 });

    if (multiplier >= 0) {
        shellcode.insert(shellcode.end(), { 0x83, 0xC0, multiplierByte });
    }
    else {
        uint8_t absMultiplier = (uint8_t)((-multiplier) & 0xFF);
        shellcode.insert(shellcode.end(), { 0x83, 0xE8, absMultiplier });
    }

    shellcode.insert(shellcode.end(), { 0xF3, 0x0F, 0x2A, 0xC8, 0x31, 0xC0 });

    size_t loopStart = shellcode.size();

    shellcode.insert(shellcode.end(), {
        0xF3, 0x41, 0x0F, 0x10, 0x04, 0x87, 0xF3, 0x0F, 0x59, 0xC1,
        0xF3, 0x41, 0x0F, 0x11, 0x44, 0x85, 0x00, 0x48, 0xFF, 0xC0,
        0x44, 0x39, 0xF0, 0x7C
        });

    size_t currentPos = shellcode.size();
    int8_t jumpBack = (int8_t)(loopStart - currentPos - 1);
    shellcode.push_back((uint8_t)jumpBack);

    size_t endLoop = shellcode.size();

    int32_t jleOffset = (int32_t)(endLoop - jleOffsetPos - 4);
    shellcode[jleOffsetPos] = (uint8_t)(jleOffset & 0xFF);
    shellcode[jleOffsetPos + 1] = (uint8_t)((jleOffset >> 8) & 0xFF);
    shellcode[jleOffsetPos + 2] = (uint8_t)((jleOffset >> 16) & 0xFF);
    shellcode[jleOffsetPos + 3] = (uint8_t)((jleOffset >> 24) & 0xFF);

    shellcode.insert(shellcode.end(), {
        0x48, 0x83, 0xC4, 0x20, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3
        });

    while (shellcode.size() < 0x1B6)
        shellcode.push_back(0x90);

    return shellcode;
}

// ============================================================================
// Apply Patch Helper
// ============================================================================
void ApplyPatch(uint8_t* fileData, uint32_t rva, const uint8_t* patch, size_t patchSize, std::vector<std::string>& logMessages)
{
    uint32_t fileOffset = RvaToFileOffset(fileData, rva);
    memcpy(fileData + fileOffset, patch, patchSize);

    char logBuffer[256];
    sprintf_s(logBuffer, "> Patched RVA 0x%X -> offset 0x%X (%zu bytes)", rva, fileOffset, patchSize);
    logMessages.push_back(logBuffer);
}

void ApplyPatch(uint8_t* fileData, uint32_t rva, uint8_t byte, std::vector<std::string>& logMessages)
{
    uint32_t fileOffset = RvaToFileOffset(fileData, rva);
    fileData[fileOffset] = byte;

    char logBuffer[256];
    sprintf_s(logBuffer, "> Patched RVA 0x%X -> offset 0x%X (byte 0x%02X)", rva, fileOffset, byte);
    logMessages.push_back(logBuffer);
}

// ============================================================================
// ImGui Style Configuration
// ============================================================================
void SetModernStyle()
{
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 8.0f;
    style.ChildRounding = 6.0f;
    style.FrameRounding = 6.0f;
    style.PopupRounding = 6.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding = 6.0f;
    style.TabRounding = 6.0f;
    style.WindowPadding = ImVec2(8, 8);
    style.FramePadding = ImVec2(6, 4);
    style.ItemSpacing = ImVec2(6, 4);
    style.ItemInnerSpacing = ImVec2(4, 3);
    style.IndentSpacing = 12.0f;
    style.ScrollbarSize = 8.0f;
    style.GrabMinSize = 6.0f;
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;
    style.PopupBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;

    ImVec4* colors = style.Colors;
    ImVec4 accentGreen = ImVec4(0.5f, 0.8f, 0.5f, 1.0f);
    ImVec4 accentGreenTransparent = ImVec4(0.5f, 0.8f, 0.5f, 0.5f);

    colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.10f, 0.12f, 1.0f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.10f, 0.10f, 0.12f, 1.0f);
    colors[ImGuiCol_PopupBg] = ImVec4(0.10f, 0.10f, 0.12f, 0.98f);
    colors[ImGuiCol_Border] = accentGreenTransparent;
    colors[ImGuiCol_BorderShadow] = ImVec4(0.0f, 0.0f, 0.0f, 0.2f);
    colors[ImGuiCol_FrameBg] = ImVec4(0.16f, 0.16f, 0.18f, 1.0f);
    colors[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.20f, 0.23f, 1.0f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(0.23f, 0.23f, 0.26f, 1.0f);
    colors[ImGuiCol_Button] = ImVec4(0.10f, 0.10f, 0.12f, 1.0f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.14f, 0.14f, 0.16f, 1.0f);
    colors[ImGuiCol_ButtonActive] = ImVec4(0.18f, 0.18f, 0.20f, 1.0f);
    colors[ImGuiCol_Header] = accentGreen;
    colors[ImGuiCol_HeaderHovered] = accentGreen;
    colors[ImGuiCol_HeaderActive] = accentGreen;
    colors[ImGuiCol_CheckMark] = accentGreen;
    colors[ImGuiCol_SliderGrab] = accentGreen;
    colors[ImGuiCol_SliderGrabActive] = accentGreen;
    colors[ImGuiCol_Text] = ImVec4(0.95f, 0.95f, 0.97f, 1.0f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
}

// ============================================================================
// String Utilities
// ============================================================================
std::string ReplaceString(std::string subject, const std::string& search, const std::string& replace)
{
    size_t pos = 0;
    while ((pos = subject.find(search, pos)) != std::string::npos)
    {
        subject.replace(pos, search.length(), replace);
        pos += replace.length();
    }
    return subject;
}

// ============================================================================
// Discord Version Detection
// ============================================================================
std::string GetDiscordVersion(const std::string& exePath)
{
    DWORD versionInfoSize = GetFileVersionInfoSizeA(exePath.c_str(), nullptr);
    if (versionInfoSize == 0) return "Unknown";

    std::vector<BYTE> versionData(versionInfoSize);
    if (!GetFileVersionInfoA(exePath.c_str(), 0, versionInfoSize, versionData.data()))
        return "Unknown";

    VS_FIXEDFILEINFO* fileInfo = nullptr;
    UINT fileInfoLength = 0;
    if (!VerQueryValueA(versionData.data(), "\\", (LPVOID*)&fileInfo, &fileInfoLength))
        return "Unknown";

    return std::to_string(HIWORD(fileInfo->dwFileVersionMS)) + "." +
        std::to_string(LOWORD(fileInfo->dwFileVersionMS)) + "." +
        std::to_string(HIWORD(fileInfo->dwFileVersionLS)) + "." +
        std::to_string(LOWORD(fileInfo->dwFileVersionLS));
}

// ============================================================================
// File System Operations
// ============================================================================
bool DeleteDirectoryContents(const std::string& directoryPath)
{
    WIN32_FIND_DATAA findData;
    std::string searchPattern = directoryPath + "\\*";
    HANDLE findHandle = FindFirstFileA(searchPattern.c_str(), &findData);

    if (findHandle == INVALID_HANDLE_VALUE) return true;

    bool success = true;
    do
    {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
            continue;

        std::string fullPath = directoryPath + "\\" + findData.cFileName;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (!DeleteDirectoryContents(fullPath)) success = false;
            RemoveDirectoryA(fullPath.c_str());
        }
        else
        {
            if (!DeleteFileA(fullPath.c_str())) success = false;
        }
    } while (FindNextFileA(findHandle, &findData) != 0);

    FindClose(findHandle);
    return success;
}


// ============================================================================
// Path Safety Validation
// ============================================================================
bool IsSafePath(const std::string& path, std::vector<std::string>& logMessages)
{
    if (path.empty())
    {
        logMessages.push_back("> ERROR: Path is empty");
        return false;
    }

    if (path.find("Discord") == std::string::npos)
    {
        logMessages.push_back("> ERROR: Path does not contain 'Discord'");
        return false;
    }

    if (path.find("modules") == std::string::npos)
    {
        logMessages.push_back("> ERROR: Path does not contain 'modules'");
        return false;
    }

    if (path.find("discord_voice") == std::string::npos)
    {
        logMessages.push_back("> ERROR: Path does not contain 'discord_voice'");
        return false;
    }

    if (path.length() < 50)
    {
        logMessages.push_back("> ERROR: Path too short, may be unsafe: " + path);
        return false;
    }

    std::string lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

    if (lowerPath == "c:\\" || lowerPath == "c:\\windows" ||
        lowerPath == "c:\\windows\\system32" ||
        lowerPath == "c:\\program files" ||
        lowerPath == "c:\\program files (x86)" ||
        lowerPath.find(":\\windows\\") != std::string::npos)
    {
        logMessages.push_back("> ERROR: Path points to system directory: " + path);
        return false;
    }

    return true;
}

// ============================================================================
// Network Operations
// ============================================================================
bool DownloadFileFromGitHub(const std::string& url, const std::string& savePath, std::vector<std::string>& logMessages)
{
    HINTERNET internetHandle = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        INTERNET_OPEN_TYPE_DIRECT,
        NULL,
        NULL,
        0
    );

    HINTERNET urlHandle = InternetOpenUrlA(
        internetHandle,
        url.c_str(),
        nullptr,
        0,
        INTERNET_FLAG_RELOAD |
        INTERNET_FLAG_SECURE |
        INTERNET_FLAG_NO_CACHE_WRITE |
        INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
        INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
        0
    );

    HANDLE fileHandle = CreateFileA(savePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        logMessages.push_back("> ERROR: Cannot create file: " + savePath + " (error " + std::to_string(err) + ")");
        InternetCloseHandle(urlHandle);
        InternetCloseHandle(internetHandle);
        return false;
    }

    char downloadBuffer[8192];
    DWORD bytesRead = 0;
    DWORD totalBytesWritten = 0;
    bool downloadSuccess = true;

    while (InternetReadFile(urlHandle, downloadBuffer, sizeof(downloadBuffer), &bytesRead) && bytesRead > 0)
    {
        DWORD bytesWritten = 0;
        if (!WriteFile(fileHandle, downloadBuffer, bytesRead, &bytesWritten, NULL))
        {
            downloadSuccess = false;
            break;
        }
        totalBytesWritten += bytesWritten;
    }

    CloseHandle(fileHandle);
    InternetCloseHandle(urlHandle);
    InternetCloseHandle(internetHandle);

    if (downloadSuccess)
    {
        std::string fileName = savePath.substr(savePath.find_last_of("\\") + 1);
        logMessages.push_back("> Downloaded: " + fileName + " (" + std::to_string(totalBytesWritten) + " bytes)");
    }

    return downloadSuccess;
}

// ============================================================================
// Discord Process Management
// ============================================================================
// ============================================================================
// Discord Process Management - Fixed to only close specific version
// ============================================================================
void CloseDiscordProcess(const std::string& discordVersion, std::vector<std::string>& logMessages)
{
    std::wstring processName;
    if (discordVersion == "Stable")
    {
        processName = L"Discord.exe";
    }
    else if (discordVersion == "PTB")
    {
        processName = L"DiscordPTB.exe";
    }
    else if (discordVersion == "Canary")
    {
        processName = L"DiscordCanary.exe";
    }
    else
    {
        logMessages.push_back("> ERROR: Unknown Discord version");
        return;
    }

    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
    {
        logMessages.push_back("> ERROR: Could not create process snapshot");
        return;
    }

    PROCESSENTRY32W ProcessEntry = {};
    ProcessEntry.dwSize = sizeof(ProcessEntry);

    int processCount = 0;
    if (Process32FirstW(Snapshot, &ProcessEntry))
    {
        do
        {
            if (_wcsicmp(ProcessEntry.szExeFile, processName.c_str()) == 0)
            {
                HANDLE Process = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessEntry.th32ProcessID);
                if (Process)
                {
                    TerminateProcess(Process, 0);
                    CloseHandle(Process);
                    processCount++;
                }
            }
        } while (Process32NextW(Snapshot, &ProcessEntry));
    }

    CloseHandle(Snapshot);

    if (processCount > 0)
    {
        logMessages.push_back("> Closed " + std::to_string(processCount) + " " + discordVersion + " process(es)");
        Sleep(1000);
    }
    else
    {
        logMessages.push_back("> No " + discordVersion + " processes found running");
    }
}


bool IsDiscordRunning(const std::string& discordVersion)
{
    std::wstring processName;
    if (discordVersion == "Stable")
    {
        processName = L"Discord.exe";
    }
    else if (discordVersion == "PTB")
    {
        processName = L"DiscordPTB.exe";
    }
    else if (discordVersion == "Canary")
    {
        processName = L"DiscordCanary.exe";
    }
    else
    {
        return false;
    }

    HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Snapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W ProcessEntry = {};
    ProcessEntry.dwSize = sizeof(ProcessEntry);

    bool isRunning = false;
    if (Process32FirstW(Snapshot, &ProcessEntry))
    {
        do
        {
            if (_wcsicmp(ProcessEntry.szExeFile, processName.c_str()) == 0)
            {
                isRunning = true;
                break;
            }
        } while (Process32NextW(Snapshot, &ProcessEntry));
    }

    CloseHandle(Snapshot);
    return isRunning;
}

// ============================================================================
// Binary Patching - Apply All Patches to discord_voice.node
// ============================================================================
bool ApplyVoiceNodePatches(const std::string& filePath, int multiplier, std::vector<std::string>& logMessages, bool& shouldScrollLog)
{
    int userGain = 2 + multiplier;
    logMessages.push_back("> Applying patches with " + std::to_string(userGain) + "x gain (multiplier=" + std::to_string(multiplier) + ")...");
    shouldScrollLog = true;

    std::ifstream inFile(filePath, std::ios::binary | std::ios::ate);
    if (!inFile.is_open())
    {
        logMessages.push_back("> ERROR: Cannot open discord_voice.node for reading");
        shouldScrollLog = true;
        return false;
    }

    std::streamsize fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    std::vector<uint8_t> fileData(fileSize);
    if (!inFile.read(reinterpret_cast<char*>(fileData.data()), fileSize))
    {
        logMessages.push_back("> ERROR: Cannot read discord_voice.node");
        shouldScrollLog = true;
        return false;
    }
    inFile.close();

    logMessages.push_back("> Loaded " + std::to_string(fileSize) + " bytes");
    shouldScrollLog = true;

    std::string backupPath = filePath + ".backup";
    if (GetFileAttributesA(backupPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::ofstream backup(backupPath, std::ios::binary);
        if (backup.is_open())
        {
            backup.write(reinterpret_cast<char*>(fileData.data()), fileSize);
            backup.close();
            logMessages.push_back("> Created backup");
            shouldScrollLog = true;
        }
    }

    logMessages.push_back("> Applying stereo emulation...");
    ApplyPatch(fileData.data(), EmulateStereoSuccess1, (uint8_t)0x02, logMessages);
    ApplyPatch(fileData.data(), EmulateStereoSuccess2, (uint8_t)0xEB, logMessages);

    logMessages.push_back("> Applying audio frame stereo...");
    const uint8_t stereoInstr[] = { 0x49, 0x89, 0xC5, 0x90 };
    ApplyPatch(fileData.data(), CreateAudioFrameStereoInstruction, stereoInstr, sizeof(stereoInstr), logMessages);

    logMessages.push_back("> Applying channel configuration...");
    ApplyPatch(fileData.data(), AudioEncoderOpusConfigSetChannelsInstruction, (uint8_t)0x02, logMessages);

    logMessages.push_back("> Applying mono downmixer...");
    const uint8_t monoDownmixer[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xE9 };
    ApplyPatch(fileData.data(), MonoDownmixerInstructions, monoDownmixer, sizeof(monoDownmixer), logMessages);

    logMessages.push_back("> Applying bitrate...");
    const uint8_t bitrateModified[] = { 0x00, 0xEE, 0x02 };
    ApplyPatch(fileData.data(), EmulateBitrateModified, bitrateModified, sizeof(bitrateModified), logMessages);

    logMessages.push_back("> Applying high-pass filter process...");
    const uint8_t hpProcess[] = { 0x48, 0xB8, 0x10, 0x9E, 0xD8, 0xCF, 0x08, 0x02, 0x00, 0x00, 0xC3 };
    ApplyPatch(fileData.data(), HighPassFilter_Process, hpProcess, sizeof(hpProcess), logMessages);

    logMessages.push_back("> Generating hp_cutoff shellcode...");
    auto hpCutoffCode = GenerateHpCutoffShellcode(multiplier);
    ApplyPatch(fileData.data(), HighpassCutoffFilter, hpCutoffCode.data(), hpCutoffCode.size(), logMessages);

    logMessages.push_back("> Generating dc_reject shellcode...");
    auto dcRejectCode = GenerateDcRejectShellcode(multiplier);
    ApplyPatch(fileData.data(), DcReject, dcRejectCode.data(), dcRejectCode.size(), logMessages);

    logMessages.push_back("> Applying downmix function...");
    ApplyPatch(fileData.data(), downmix_func, (uint8_t)0xC3, logMessages);

    logMessages.push_back("> Applying 48kHz emulation...");
    const uint8_t emulate48khz[] = { 0x90, 0x90, 0x90 };
    ApplyPatch(fileData.data(), Emulate48Khz, emulate48khz, sizeof(emulate48khz), logMessages);

    logMessages.push_back("> Applying opus config validation...");
    const uint8_t isOk[] = { 0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, 0xC3 };
    ApplyPatch(fileData.data(), AudioEncoderOpusConfig_IsOk, isOk, sizeof(isOk), logMessages);

    logMessages.push_back("> Applying bitrate value (510000)...");
    const uint8_t bitrateValue[] = { 0x30, 0xC8, 0x07, 0x00, 0x00 };
    ApplyPatch(fileData.data(), SetsBitrate_BitrateValue, bitrateValue, sizeof(bitrateValue), logMessages);

    logMessages.push_back("> Applying bitrate OR operation...");
    const uint8_t bitwiseOr[] = { 0x90, 0x90, 0x90 };
    ApplyPatch(fileData.data(), SetsBitrate_BitwiseOr, bitwiseOr, sizeof(bitwiseOr), logMessages);

    logMessages.push_back("> Applying error handler...");
    ApplyPatch(fileData.data(), ThrowError, (uint8_t)0xC3, logMessages);

    shouldScrollLog = true;

    logMessages.push_back("> Writing patched file...");
    shouldScrollLog = true;

    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile.is_open())
    {
        logMessages.push_back("> ERROR: Cannot write to discord_voice.node");
        logMessages.push_back("> Make sure Discord is completely closed");
        shouldScrollLog = true;
        return false;
    }

    outFile.write(reinterpret_cast<char*>(fileData.data()), fileSize);
    outFile.close();

    logMessages.push_back("> Successfully patched discord_voice.node!");
    logMessages.push_back("> Gain: " + std::to_string(userGain) + "x, Stereo: Enabled, Bitrate: 510000 bps");
    shouldScrollLog = true;

    return true;
}

// ============================================================================
// Main Patch Function
// ============================================================================
bool PerformDiscordPatch(std::vector<std::string>& logMessages, bool& shouldScrollLog,
    const char* discordVersion, int multiplier)
{
    logMessages.push_back("> Starting patch for " + std::string(discordVersion) + "...");
    shouldScrollLog = true;

    char localAppDataPath[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath)))
    {
        logMessages.push_back("> ERROR: Could not find LocalAppData");
        shouldScrollLog = true;
        return false;
    }

    std::string discordFolderName;
    if (strcmp(discordVersion, "Stable") == 0) discordFolderName = "Discord";
    else if (strcmp(discordVersion, "PTB") == 0) discordFolderName = "DiscordPTB";
    else if (strcmp(discordVersion, "Canary") == 0) discordFolderName = "DiscordCanary";

    std::string discordBasePath = std::string(localAppDataPath) + "\\" + discordFolderName;

    if (IsDiscordRunning(discordVersion))
    {
        logMessages.push_back("> Discord is running, closing all processes...");
        shouldScrollLog = true;
        CloseDiscordProcess(discordVersion, logMessages);

        int attempts = 0;
        while (IsDiscordRunning(discordVersion) && attempts < 10)
        {
            Sleep(500);
            CloseDiscordProcess(discordVersion, logMessages);
            attempts++;
        }

        if (IsDiscordRunning(discordVersion))
        {
            logMessages.push_back("> ERROR: Failed to close Discord. Please close manually.");
            shouldScrollLog = true;
            return false;
        }
    }

    WIN32_FIND_DATAA findData;
    std::string appSearchPattern = discordBasePath + "\\app-*";
    HANDLE findHandle = FindFirstFileA(appSearchPattern.c_str(), &findData);

    std::string latestAppDirectory;
    if (findHandle != INVALID_HANDLE_VALUE)
    {
        latestAppDirectory = discordBasePath + "\\" + findData.cFileName;
        do
        {
            if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0)
            {
                std::string currentDirectory = discordBasePath + "\\" + findData.cFileName;
                if (currentDirectory > latestAppDirectory)
                    latestAppDirectory = currentDirectory;
            }
        } while (FindNextFileA(findHandle, &findData) != 0);
        FindClose(findHandle);
    }

    std::string voiceModuleSearchPattern = latestAppDirectory + "\\modules\\discord_voice-*";
    findHandle = FindFirstFileA(voiceModuleSearchPattern.c_str(), &findData);

    std::string voiceModuleDirectory;
    if (findHandle != INVALID_HANDLE_VALUE)
    {
        std::string baseVoiceDir = latestAppDirectory + "\\modules\\" + findData.cFileName;
        FindClose(findHandle);

        std::string nestedVoiceDir = baseVoiceDir + "\\discord_voice";
        if (PathFileExistsA(nestedVoiceDir.c_str()))
        {
            voiceModuleDirectory = nestedVoiceDir;
        }
        else
        {
            voiceModuleDirectory = baseVoiceDir;
        }
    }

    logMessages.push_back("> Voice module path: " + voiceModuleDirectory);
    shouldScrollLog = true;

    if (!IsSafePath(voiceModuleDirectory, logMessages))
    {
        logMessages.push_back("> ERROR: Unsafe path detected, aborting operation");
        shouldScrollLog = true;
        return false;
    }

    logMessages.push_back("> Path validation passed");
    shouldScrollLog = true;

    logMessages.push_back("> Clearing voice module directory...");
    DeleteDirectoryContents(voiceModuleDirectory);
    shouldScrollLog = true;

    std::vector<std::string> requiredFiles = {
        "discord_voice.node", "gpu_encoder_helper.exe", "index.js", "manifest.json",
        "mediapipe.dll", "package.json", "selfie_segmentation.tflite",
        "selfie_segmentation_landscape.tflite",
    };

    std::string githubBaseUrl = "https://raw.githubusercontent.com/sh6un/Stereo-Installation-Files/main/NewVoiceModules/";

    for (const auto& fileName : requiredFiles)
    {
        std::string fileUrl = githubBaseUrl + fileName;
        std::string localFilePath = voiceModuleDirectory + "\\" + fileName;
        if (!DownloadFileFromGitHub(fileUrl, localFilePath, logMessages))
        {
            logMessages.push_back("> ERROR: Failed to download " + fileName);
            shouldScrollLog = true;
            return false;
        }
        shouldScrollLog = true;
    }

    std::string voiceNodePath = voiceModuleDirectory + "\\discord_voice.node";

    logMessages.push_back("> Waiting for file system to settle...");
    shouldScrollLog = true;
    Sleep(500);

    if (!ApplyVoiceNodePatches(voiceNodePath, multiplier, logMessages, shouldScrollLog))
    {
        logMessages.push_back("> ERROR: Failed to apply patches");
        shouldScrollLog = true;
        return false;
    }

    logMessages.push_back("> Patch completed successfully!");
    shouldScrollLog = true;
    return true;
}

// ============================================================================
// Discord Version Display Update
// ============================================================================
void UpdateDiscordVersion(char* versionBuffer, size_t bufferSize, const char* discordVersion)
{
    char localAppDataPath[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppDataPath)))
    {
        strcpy_s(versionBuffer, bufferSize, "Unknown");
        return;
    }

    std::string discordFolderName;
    std::string executableName;

    if (strcmp(discordVersion, "Stable") == 0)
    {
        discordFolderName = "Discord";
        executableName = "Discord.exe";
    }
    else if (strcmp(discordVersion, "PTB") == 0)
    {
        discordFolderName = "DiscordPTB";
        executableName = "DiscordPTB.exe";
    }
    else if (strcmp(discordVersion, "Canary") == 0)
    {
        discordFolderName = "DiscordCanary";
        executableName = "DiscordCanary.exe";
    }

    std::string discordBasePath = std::string(localAppDataPath) + "\\" + discordFolderName;

    WIN32_FIND_DATAA findData;
    std::string appSearchPattern = discordBasePath + "\\app-*";
    HANDLE findHandle = FindFirstFileA(appSearchPattern.c_str(), &findData);

    std::string discordExecutablePath;

    if (findHandle != INVALID_HANDLE_VALUE)
    {
        std::string latestDirectory = findData.cFileName;

        do
        {
            if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0)
            {
                std::string currentDirectory = findData.cFileName;
                if (currentDirectory > latestDirectory)
                {
                    latestDirectory = currentDirectory;
                }
            }
        } while (FindNextFileA(findHandle, &findData) != 0);

        FindClose(findHandle);
        discordExecutablePath = discordBasePath + "\\" + latestDirectory + "\\" + executableName;
    }

    if (discordExecutablePath.empty())
    {
        discordExecutablePath = discordBasePath + "\\" + executableName;
    }

    DWORD fileAttributes = GetFileAttributesA(discordExecutablePath.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES || (fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        strcpy_s(versionBuffer, bufferSize, "Not Found");
        return;
    }

    std::string version = GetDiscordVersion(discordExecutablePath);
    strcpy_s(versionBuffer, bufferSize, version.c_str());
}


// ============================================================================
// Equaliser APO Fix
// ============================================================================
bool FixEqualiserAPO(std::vector<std::string>& logMessages, bool& shouldScrollLog, const char* discordVersion)
{
    logMessages.push_back("> Locating Discord settings...");
    shouldScrollLog = true;

    char appDataPath[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appDataPath)))
    {
        logMessages.push_back("> ERROR: Could not find AppData folder");
        shouldScrollLog = true;
        return false;
    }

    std::string discordFolderName;
    if (strcmp(discordVersion, "Stable") == 0)
    {
        discordFolderName = "discord";
    }
    else if (strcmp(discordVersion, "PTB") == 0)
    {
        discordFolderName = "discordptb";
    }
    else if (strcmp(discordVersion, "Canary") == 0)
    {
        discordFolderName = "discordcanary";
    }

    std::string settingsFilePath = std::string(appDataPath) + "\\" + discordFolderName + "\\settings.json";
    logMessages.push_back("> Target: " + discordFolderName);
    logMessages.push_back("> Found: " + settingsFilePath);
    shouldScrollLog = true;

    std::ifstream inputFile(settingsFilePath);
    if (!inputFile.is_open())
    {
        logMessages.push_back("> ERROR: Could not open settings.json");
        logMessages.push_back("> Make sure " + std::string(discordVersion) + " Discord has been run at least once");
        shouldScrollLog = true;
        return false;
    }

    std::string fileContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    bool settingsModified = false;

    if (fileContent.find("\"audioSubsystem\"") != std::string::npos)
    {
        if (fileContent.find("\"audioSubsystem\": \"standard\"") != std::string::npos ||
            fileContent.find("\"audioSubsystem\": \"legacy\"") != std::string::npos)
        {
            fileContent = ReplaceString(fileContent, "\"audioSubsystem\": \"standard\"", "\"audioSubsystem\": \"experimental\"");
            fileContent = ReplaceString(fileContent, "\"audioSubsystem\": \"legacy\"", "\"audioSubsystem\": \"experimental\"");
            logMessages.push_back("> Set audioSubsystem to experimental");
            shouldScrollLog = true;
            settingsModified = true;
        }
    }
    else
    {
        size_t insertPosition = fileContent.find_last_of('}');
        if (insertPosition != std::string::npos)
        {
            fileContent.insert(insertPosition, ",\n  \"audioSubsystem\": \"experimental\"");
            logMessages.push_back("> Added audioSubsystem: experimental");
            shouldScrollLog = true;
            settingsModified = true;
        }
    }



    if (settingsModified)
    {
        std::ofstream outputFile(settingsFilePath);
        if (!outputFile.is_open())
        {
            logMessages.push_back("> ERROR: Could not write to settings.json");
            shouldScrollLog = true;
            return false;
        }
        outputFile << fileContent;
        outputFile.close();

        logMessages.push_back("> Settings updated successfully for " + std::string(discordVersion) + "!");
        logMessages.push_back("> IMPORTANT: Turn OFF 'Bypass System Audio Input Processing' in Discord");
        shouldScrollLog = true;
        return true;
    }
    else
    {
        logMessages.push_back("> Settings already correct.");
        shouldScrollLog = true;
        return true;
    }
}
// ============================================================================
// Main Application Entry Point
// ============================================================================
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    ImGui_ImplWin32_EnableDpiAwareness();
    float dpiScale = ImGui_ImplWin32_GetDpiScaleForMonitor(MonitorFromPoint({ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW windowClass = { sizeof(windowClass), CS_CLASSDC, WndProc, 0L, 0L,
                                GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr,
                                L"StereoPatcher", nullptr };
    RegisterClassExW(&windowClass);

    int scaledWidth = (int)(WINDOW_WIDTH * dpiScale);
    int scaledHeight = (int)(WINDOW_HEIGHT * dpiScale);
    HWND windowHandle = CreateWindowW(windowClass.lpszClassName, L"Stereo Patcher", WS_POPUP,
        100, 100, scaledWidth, scaledHeight,
        nullptr, nullptr, windowClass.hInstance, nullptr);

    HRGN roundedRegion = CreateRoundRectRgn(0, 0, scaledWidth + 1, scaledHeight + 1,
        WINDOW_CORNER_RADIUS, WINDOW_CORNER_RADIUS);
    SetWindowRgn(windowHandle, roundedRegion, TRUE);

    if (!CreateDeviceD3D(windowHandle))
    {
        CleanupDeviceD3D();
        return 1;
    }

    ShowWindow(windowHandle, SW_SHOWDEFAULT);
    UpdateWindow(windowHandle);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigWindowsResizeFromEdges = true;
    io.MouseDrawCursor = false;
    io.ConfigWindowsMoveFromTitleBarOnly = true;
     
    ImFont* df = io.Fonts->AddFontDefault();
     
    static const ImWchar icons_ranges[] = { ICON_MIN_FA, ICON_MAX_16_FA, 0 };
    ImFontConfig fa_config;
    fa_config.MergeMode = true;
    fa_config.PixelSnapH = true;
    fa_config.GlyphMinAdvanceX = 14.0f; 

    io.Fonts->AddFontFromMemoryCompressedTTF(
        fa6_solid_compressed_data,
        fa6_solid_compressed_size,
        14.0f,
        &fa_config,
        icons_ranges
    );

    SetModernStyle();
    ImGui::GetStyle().ScaleAllSizes(dpiScale);

    ImGui_ImplWin32_Init(windowHandle);
    ImGui_ImplDX11_Init(g_D3D11Device, g_D3D11DeviceContext);

    bool applicationRunning = true;
    Page currentPage = PAGE_HOME;

    std::vector<std::string> logMessages = {
        "Initialising...",
        "Select destination, version and gain type",
        "Waiting for user action...",
    };

    char versionDisplayBuffer[128] = "Checking...";

    static const char* discordVersions[] = { "Stable", "PTB", "Canary" };
    static const char* gainTypes[] = { "Base Module (1x)", "2x Gain", "5x Gain", "10x Gain" };
    static int gainMultipliers[] = { -1, 0, 3, 8 };

    static int selectedDiscordVersion = 0;
    static int selectedGainType = 0;
    static int previousDiscordVersion = -1;
    static bool shouldScrollLog = false;

    while (applicationRunning)
    {
        MSG message;
        while (PeekMessage(&message, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessage(&message);
            if (message.message == WM_QUIT)
            {
                applicationRunning = false;
            }
        }

        if (!applicationRunning) break;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
        {
            CleanupRenderTarget();
            g_SwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);

        ImGuiWindowFlags mainWindowFlags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBringToFrontOnFocus;

        ImGui::Begin("##MainWindow", nullptr, mainWindowFlags);

        ImGui::SetCursorPos(ImVec2(0, 0));
        ImGui::InvisibleButton("##titlebar", ImVec2(ImGui::GetWindowWidth() - 30, 32));

        if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left))
        {
            if (!g_IsDragging)
            {
                g_IsDragging = true;
                POINT cursorPosition;
                GetCursorPos(&cursorPosition);
                RECT windowRect;
                GetWindowRect(windowHandle, &windowRect);
                g_DragOffset.x = (float)(cursorPosition.x - windowRect.left);
                g_DragOffset.y = (float)(cursorPosition.y - windowRect.top);
            }

            POINT cursorPosition;
            GetCursorPos(&cursorPosition);
            SetWindowPos(windowHandle, nullptr,
                cursorPosition.x - (int)g_DragOffset.x,
                cursorPosition.y - (int)g_DragOffset.y,
                0, 0, SWP_NOSIZE | SWP_NOZORDER);
        }
        else
        {
            g_IsDragging = false;
        }

        ImGui::SetCursorPos(ImVec2(0, 8));
        float titleTextWidth = ImGui::CalcTextSize("STEREO PATCHER").x;
        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - titleTextWidth) * 0.5f);
        ImGui::TextColored(ImVec4(0.8f, 1.0f, 0.8f, 1.0f), "STEREO PATCHER");

        ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 28, 6));
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 0.3f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
        if (ImGui::Button("X##close", ImVec2(20, 20)))
        {
            applicationRunning = false;
        }
        ImGui::PopStyleColor(3);

        ImGui::SetCursorPosY(32);
        ImGui::Separator();

        ImGui::SetCursorPosY(38);
        ImGui::BeginChild("ContentArea", ImVec2(0, -65), false,
            ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        {
            if (currentPage == PAGE_HOME)
            {
                ImGui::Spacing();
                ImGui::Spacing();

                if (selectedDiscordVersion != previousDiscordVersion)
                {
                    UpdateDiscordVersion(versionDisplayBuffer, sizeof(versionDisplayBuffer),
                        discordVersions[selectedDiscordVersion]);
                    previousDiscordVersion = selectedDiscordVersion;
                }

                ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.06f, 0.06f, 0.08f, 1.0f));
                ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 6.0f);
                ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6, 6));

                float logBoxWidth = ImGui::GetWindowWidth() - 24;
                float logBoxPosX = (ImGui::GetWindowWidth() - logBoxWidth) * 0.5f;
                ImGui::SetCursorPosX(logBoxPosX);

                ImGui::BeginChild("LogBox", ImVec2(logBoxWidth, 100), true);
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.8f, 0.6f, 1.0f));
                    ImGui::Text("Output Log");
                    ImGui::PopStyleColor();
                    ImGui::Separator();

                    for (const auto& logMessage : logMessages)
                    {
                        ImGui::TextWrapped("%s", logMessage.c_str());
                    }

                    if (shouldScrollLog)
                    {
                        ImGui::SetScrollHereY(1.0f);
                        shouldScrollLog = false;
                    }
                }
                ImGui::EndChild();
                ImGui::PopStyleVar(2);
                ImGui::PopStyleColor();
                ImGui::Spacing();

                ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
                ImGui::Columns(3, nullptr, false);
                ImGui::SetColumnWidth(0, ImGui::GetWindowWidth() * 0.33f - 6);
                ImGui::SetColumnWidth(1, ImGui::GetWindowWidth() * 0.33f - 6);

                ImGui::Text("Destination");
                ImGui::SetNextItemWidth(-1);
                ImGui::Combo("##destination", &selectedDiscordVersion, discordVersions, IM_ARRAYSIZE(discordVersions));

                ImGui::NextColumn();

                ImGui::Text("Gain Type");
                ImGui::SetNextItemWidth(-1);
                ImGui::Combo("##gaintype", &selectedGainType, gainTypes, IM_ARRAYSIZE(gainTypes));

                ImGui::NextColumn();

                ImGui::Text("Version");
                ImGui::SetNextItemWidth(-1);
                ImGui::BeginDisabled(true);
                ImGui::InputText("##version", versionDisplayBuffer, IM_ARRAYSIZE(versionDisplayBuffer));
                ImGui::EndDisabled();

                ImGui::Columns(1);
                ImGui::PopStyleVar();
            }
            else if (currentPage == PAGE_SETTINGS)
            {
                ImGui::Spacing();
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.8f, 1.0f, 0.8f, 1.0f), "SETTINGS");
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                ImGui::BeginChild("SettingsContent", ImVec2(0, 0), true);
                {
                    static bool autoUpdateEnabled = true;
                    static bool notificationsEnabled = true;

                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();
                    ImGui::Text("About");
                    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
                    ImGui::TextWrapped("Stereo Patcher v2.0.0");
                    ImGui::TextWrapped("Stereo Installer by @sh6un");
                    ImGui::TextWrapped("Credit to ProdHallow [Multiplication & Patcher Logic] and Loof-Sys/Cypher [Offsets, Patching Instructions, Patching Logic]");
                    ImGui::PopStyleColor();
                }
                ImGui::EndChild();
            }
            else if (currentPage == PAGE_TROUBLESHOOT)
            {
                ImGui::Spacing();
                ImGui::Spacing();
                ImGui::TextColored(ImVec4(0.8f, 1.0f, 0.8f, 1.0f), "TROUBLESHOOTING");
                ImGui::Spacing();
                ImGui::Separator();
                ImGui::Spacing();

                ImGui::BeginChild("TroubleshootContent", ImVec2(0, 0), true);
                {
                    ImGui::Text("Common Issues:");
                    ImGui::Spacing();
                    ImGui::TextDisabled("- Equalizer APO refusing to work due to Discord settings.");
                    ImGui::TextDisabled("- RTC connecting due to unsupported index.js file.");
                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();

                    if (ImGui::Button("Fix Equaliser APO", ImVec2(-1, 26)))
                    {
                        FixEqualiserAPO(logMessages, shouldScrollLog, discordVersions[selectedDiscordVersion]);
                    }
                }
                ImGui::EndChild();
            }
        }
        ImGui::EndChild();

        if (currentPage == PAGE_HOME)
        {
            constexpr float patchButtonWidth = 120.0f;
            ImVec2 windowSize = ImGui::GetWindowSize();
            float buttonPosX = (windowSize.x - patchButtonWidth) * 0.5f;
            float buttonPosY = windowSize.y - 70;

            ImGui::SetCursorPos(ImVec2(buttonPosX, buttonPosY));

            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.25f, 0.55f, 0.25f, 0.4f));
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.30f, 0.65f, 0.30f, 0.6f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.35f, 0.70f, 0.35f, 0.8f));
            ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);

            if (ImGui::Button("PATCH##smallpatch", ImVec2(patchButtonWidth, 22)))
            {
                logMessages.clear();
                logMessages.push_back("> Starting patch...");
                logMessages.push_back("> Analyzing Discord installation...");

                int currentMultiplier = gainMultipliers[selectedGainType];

                if (PerformDiscordPatch(logMessages, shouldScrollLog,
                    discordVersions[selectedDiscordVersion],
                    currentMultiplier))
                {
                    logMessages.push_back("> Operation completed successfully!");
                }
                else
                {
                    logMessages.push_back("> Operation failed!");
                }

                shouldScrollLog = true;

                if (logMessages.size() > 100)
                {
                    while (logMessages.size() > 100)
                    {
                        logMessages.erase(logMessages.begin());
                    }
                }
            }

            ImGui::PopStyleVar();
            ImGui::PopStyleColor(3);
        }

        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 46);
        ImGui::Separator();

        constexpr float navButtonSize = 28.0f;
        constexpr float navButtonSpacing = 10.0f;
        float totalNavWidth = navButtonSize * 3 + navButtonSpacing * 2;

        ImGui::SetCursorPosX((ImGui::GetWindowWidth() - totalNavWidth) / 2.0f);
        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 38);

        ImVec4 navActiveColor = ImVec4(0.40f, 0.60f, 0.40f, 1.0f);
        ImVec4 navInactiveColor = ImVec4(0.20f, 0.25f, 0.20f, 1.0f);
        ImVec4 navHoverColor = ImVec4(0.45f, 0.65f, 0.45f, 1.0f);
        ImVec4 navActiveTextColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        ImVec4 navInactiveTextColor = ImVec4(0.7f, 0.7f, 0.7f, 1.0f);

        ImGui::PushID("home_button");
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 8.0f));
        ImGui::PushStyleColor(ImGuiCol_Button, (currentPage == PAGE_HOME) ? navActiveColor : navInactiveColor);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, navHoverColor);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, navHoverColor);
        ImGui::PushStyleColor(ImGuiCol_Text, (currentPage == PAGE_HOME) ? navActiveTextColor : navInactiveTextColor);  
        if (ImGui::Button(ICON_FA_HOUSE, ImVec2(navButtonSize, navButtonSize)))
        {
            currentPage = PAGE_HOME;
        } 
        ImGui::PopStyleColor(4);
        ImGui::PopStyleVar(2);
        ImGui::PopID();

        ImGui::SameLine(0, navButtonSpacing);

        ImGui::PushID("settings_button");
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6.0f, 9.2f));
        ImGui::PushStyleColor(ImGuiCol_Button, (currentPage == PAGE_SETTINGS) ? navActiveColor : navInactiveColor);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, navHoverColor);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, navHoverColor);
        ImGui::PushStyleColor(ImGuiCol_Text, (currentPage == PAGE_SETTINGS) ? navActiveTextColor : navInactiveTextColor);
        if (ImGui::Button(ICON_FA_GEAR, ImVec2(navButtonSize, navButtonSize)))
        {
            currentPage = PAGE_SETTINGS;
        }
        ImGui::PopStyleColor(4);
        ImGui::PopStyleVar(2);
        ImGui::PopID();

        ImGui::SameLine(0, navButtonSpacing);

        ImGui::PushID("troubleshoot_button");
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8.5f, 9.2f));
        ImGui::PushStyleColor(ImGuiCol_Button, (currentPage == PAGE_TROUBLESHOOT) ? navActiveColor : navInactiveColor);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, navHoverColor);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, navHoverColor);
        ImGui::PushStyleColor(ImGuiCol_Text, (currentPage == PAGE_TROUBLESHOOT) ? navActiveTextColor : navInactiveTextColor);
        if (ImGui::Button(ICON_FA_WRENCH, ImVec2(navButtonSize, navButtonSize)))
        {
            currentPage = PAGE_TROUBLESHOOT;
        }
        ImGui::PopStyleColor(4);
        ImGui::PopStyleVar(2);
        ImGui::PopID();

        ImGui::End();

        ImGui::Begin("##MainWindow", nullptr, mainWindowFlags);
        ImVec2 windowPosition = ImGui::GetWindowPos();
        ImVec2 windowSize = ImGui::GetWindowSize();
        ImGui::End();

        ImDrawList* foregroundDrawList = ImGui::GetForegroundDrawList();
        foregroundDrawList->AddRect(
            windowPosition,
            ImVec2(windowPosition.x + windowSize.x, windowPosition.y + windowSize.y),
            IM_COL32(128, 204, 128, 128),
            BORDER_ROUNDING,
            0,
            BORDER_THICKNESS
        );

        ImGui::Render();
        const float clearColor[4] = { 0.08f, 0.08f, 0.10f, 1.0f };
        g_D3D11DeviceContext->OMSetRenderTargets(1, &g_MainRenderTargetView, nullptr);
        g_D3D11DeviceContext->ClearRenderTargetView(g_MainRenderTargetView, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        HRESULT presentResult = g_SwapChain->Present(1, 0);
        g_SwapChainOccluded = (presentResult == DXGI_STATUS_OCCLUDED);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(windowHandle);
    UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);

    return 0;
}

// ============================================================================
// D3D11 Device Creation
// ============================================================================
bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC swapChainDesc = {};
    swapChainDesc.BufferCount = 2;
    swapChainDesc.BufferDesc.Width = 0;
    swapChainDesc.BufferDesc.Height = 0;
    swapChainDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swapChainDesc.BufferDesc.RefreshRate.Numerator = 60;
    swapChainDesc.BufferDesc.RefreshRate.Denominator = 1;
    swapChainDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swapChainDesc.OutputWindow = hWnd;
    swapChainDesc.SampleDesc.Count = 1;
    swapChainDesc.SampleDesc.Quality = 0;
    swapChainDesc.Windowed = TRUE;
    swapChainDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    swapChainDesc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    HRESULT result = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        featureLevelArray,
        2,
        D3D11_SDK_VERSION,
        &swapChainDesc,
        &g_SwapChain,
        &g_D3D11Device,
        &featureLevel,
        &g_D3D11DeviceContext
    );

    if (result != S_OK) return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_SwapChain) { g_SwapChain->Release(); g_SwapChain = nullptr; }
    if (g_D3D11DeviceContext) { g_D3D11DeviceContext->Release(); g_D3D11DeviceContext = nullptr; }
    if (g_D3D11Device) { g_D3D11Device->Release(); g_D3D11Device = nullptr; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* backBuffer = nullptr;
    g_SwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer));
    g_D3D11Device->CreateRenderTargetView(backBuffer, nullptr, &g_MainRenderTargetView);
    backBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_MainRenderTargetView) { g_MainRenderTargetView->Release(); g_MainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED)
        {
            g_ResizeWidth = LOWORD(lParam);
            g_ResizeHeight = HIWORD(lParam);
        }
        return 0;

    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}
