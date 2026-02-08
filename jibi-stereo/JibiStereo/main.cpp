#include <windows.h>
#include <shellapi.h>
#include <d3d11.h>
#include <tchar.h>

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>

#include <tlhelp32.h>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#pragma comment(lib, "d3d11.lib")

static void ApplyModernStyle()
{
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 6.0f;
    style.ChildRounding = 4.0f;
    style.FrameRounding = 0.0f; // boxy buttons/frames
    style.PopupRounding = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.GrabRounding = 0.0f;
    style.TabRounding = 4.0f;
    style.WindowBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 0.0f;
    style.ChildBorderSize = 0.0f;
    style.ScrollbarSize = 10.0f;
    style.FramePadding = ImVec2(8, 4);
    style.ItemSpacing = ImVec2(4, 4);
    style.WindowPadding = ImVec2(10, 10);

    ImVec4* colors = style.Colors;
    // Slightly brighter, violet-tinted dark theme
    const ImVec4 bg = ImVec4(0.10f, 0.09f, 0.13f, 1.00f);
    const ImVec4 panel = ImVec4(0.18f, 0.16f, 0.22f, 1.00f);
    const ImVec4 panel2 = ImVec4(0.22f, 0.20f, 0.28f, 1.00f);
    const ImVec4 accent = ImVec4(0.70f, 0.45f, 1.00f, 1.00f);      // violet accent
    const ImVec4 accentHover = ImVec4(0.80f, 0.55f, 1.00f, 1.00f);

    colors[ImGuiCol_WindowBg] = bg;
    colors[ImGuiCol_ChildBg] = ImVec4(panel.x, panel.y, panel.z, 0.95f);
    colors[ImGuiCol_PopupBg] = panel;
    colors[ImGuiCol_FrameBg] = panel2;
    colors[ImGuiCol_FrameBgHovered] = ImVec4(panel2.x + 0.03f, panel2.y + 0.03f, panel2.z + 0.03f, 1.0f);
    colors[ImGuiCol_FrameBgActive] = ImVec4(panel2.x + 0.05f, panel2.y + 0.05f, panel2.z + 0.05f, 1.0f);

    colors[ImGuiCol_Button] = ImVec4(panel2.x, panel2.y, panel2.z, 1.0f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(accent.x, accent.y, accent.z, 0.35f);
    colors[ImGuiCol_ButtonActive] = ImVec4(accent.x, accent.y, accent.z, 0.55f);

    colors[ImGuiCol_Header] = ImVec4(accent.x, accent.y, accent.z, 0.35f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(accent.x, accent.y, accent.z, 0.55f);
    colors[ImGuiCol_HeaderActive] = ImVec4(accent.x, accent.y, accent.z, 0.65f);

    colors[ImGuiCol_CheckMark] = accent;
    colors[ImGuiCol_SliderGrab] = accent;
    colors[ImGuiCol_SliderGrabActive] = accentHover;
    colors[ImGuiCol_ResizeGrip] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_ResizeGripHovered] = ImVec4(0, 0, 0, 0);
    colors[ImGuiCol_ResizeGripActive] = ImVec4(0, 0, 0, 0);

    colors[ImGuiCol_TitleBg] = bg;
    colors[ImGuiCol_TitleBgActive] = bg;
    colors[ImGuiCol_TitleBgCollapsed] = bg;

    colors[ImGuiCol_Separator] = ImVec4(accent.x, accent.y, accent.z, 0.25f);
    colors[ImGuiCol_SeparatorHovered] = ImVec4(accent.x, accent.y, accent.z, 0.30f);
    colors[ImGuiCol_SeparatorActive] = ImVec4(accent.x, accent.y, accent.z, 0.45f);

    colors[ImGuiCol_Text] = ImVec4(0.96f, 0.95f, 0.99f, 1.00f);
    colors[ImGuiCol_TextDisabled] = ImVec4(0.70f, 0.68f, 0.78f, 1.00f);
}

// ----------------------------
// Minimal ImGui + D3D11 scaffolding (based on Dear ImGui examples)
// ----------------------------
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

static void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

static void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

static bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
#ifdef _DEBUG
    createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[1] = { D3D_FEATURE_LEVEL_11_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevelArray, 1, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// ----------------------------
// Safe "patch simulation" utilities
// ----------------------------
static std::string GetLocalAppData()
{
    char buf[MAX_PATH]{};
    DWORD len = GetEnvironmentVariableA("LOCALAPPDATA", buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return ".";
    return std::string(buf);
}

static void EnsureDirExists(const std::string& path)
{
    // CreateDirectoryA only creates one level; this is enough for our fixed subdirs.
    CreateDirectoryA(path.c_str(), nullptr);
}

static void AppendLog(std::vector<std::string>& logs, const std::string& line)
{
    logs.push_back(line);
    if (logs.size() > 200) logs.erase(logs.begin());
}

// (simulation removed)

static bool DirectoryExists(const std::string& path)
{
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static bool FileExists(const std::string& path)
{
    DWORD attrs = GetFileAttributesA(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static std::vector<std::string> FindDirectoriesMatching(const std::string& parent, const std::string& pattern)
{
    std::vector<std::string> results;

    WIN32_FIND_DATAA ffd{};
    const std::string search = parent + "\\" + pattern;
    HANDLE h = FindFirstFileA(search.c_str(), &ffd);
    if (h == INVALID_HANDLE_VALUE)
        return results;

    do
    {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            const char* name = ffd.cFileName;
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0)
                results.push_back(parent + "\\" + name);
        }
    } while (FindNextFileA(h, &ffd));

    FindClose(h);
    std::sort(results.begin(), results.end());
    return results;
}

static std::string FindLatestAppDir(const std::string& base)
{
    auto apps = FindDirectoriesMatching(base, "app-*");
    if (apps.empty()) return {};
    return apps.back(); // lexical sort is OK for app-<version> directories in practice
}

static std::string FindVoiceModuleDir(const std::string& appDir)
{
    // Usually: <appDir>\modules\discord_voice-<ver>\discord_voice
    const std::string modules = appDir + "\\modules";
    if (!DirectoryExists(modules)) return {};

    auto voiceMods = FindDirectoriesMatching(modules, "discord_voice-*");
    if (voiceMods.empty()) return {};

    // pick latest
    const std::string baseVoice = voiceMods.back();
    const std::string nested = baseVoice + "\\discord_voice";
    if (DirectoryExists(nested))
        return nested;
    return baseVoice;
}

struct DetectedDiscordInfo
{
    std::string stableVoiceDir;
    std::string ptbVoiceDir;
    std::string canaryVoiceDir;
};

enum class DiscordRunState
{
    NotRunning,
    Stable,
    PTB,
    Canary
};

static DiscordRunState GetDiscordRunState()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return DiscordRunState::NotRunning;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    auto isName = [&](const wchar_t* a, const wchar_t* b) {
        return _wcsicmp(a, b) == 0;
    };

    DiscordRunState state = DiscordRunState::NotRunning;

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (isName(pe.szExeFile, L"Discord.exe")) { state = DiscordRunState::Stable; break; }
            if (isName(pe.szExeFile, L"DiscordPTB.exe")) { state = DiscordRunState::PTB; break; }
            if (isName(pe.szExeFile, L"DiscordCanary.exe")) { state = DiscordRunState::Canary; break; }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return state;
}

static void DetectDiscordInstalls(std::vector<std::string>& logs, DetectedDiscordInfo& out)
{
    out = {};
    AppendLog(logs, "Detecting Discord...");

    struct Variant { const char* label; const char* folder; std::string* outVoiceDir; } variants[] = {
        {"Stable", "Discord", &out.stableVoiceDir},
        {"PTB", "DiscordPTB", &out.ptbVoiceDir},
        {"Canary", "DiscordCanary", &out.canaryVoiceDir},
    };

    const std::string lad = GetLocalAppData();
    for (auto& v : variants)
    {
        const std::string base = lad + "\\" + v.folder;
        if (!DirectoryExists(base))
        {
            AppendLog(logs, std::string(v.label) + " not found.");
            continue;
        }

        const std::string appDir = FindLatestAppDir(base);
        if (appDir.empty())
        {
            AppendLog(logs, std::string(v.label) + " found, but installation looks incomplete.");
            continue;
        }

        AppendLog(logs, std::string(v.label) + " version folder: " + appDir);

        const std::string voiceDir = FindVoiceModuleDir(appDir);
        if (voiceDir.empty())
        {
            AppendLog(logs, std::string(v.label) + " voice files not found.");
            continue;
        }

        *v.outVoiceDir = voiceDir;
        AppendLog(logs, std::string(v.label) + " voice folder: " + voiceDir);

        const std::string node = voiceDir + "\\discord_voice.node";
        const std::string indexJs = voiceDir + "\\index.js";
        AppendLog(logs, std::string("  Voice engine file: ") + (FileExists(node) ? "OK" : "Missing"));
        AppendLog(logs, std::string("  Support file: ") + (FileExists(indexJs) ? "OK" : "Missing"));
    }

    AppendLog(logs, "Done.");
}

static void OpenFolderInExplorer(const std::string& path, std::vector<std::string>& logs)
{
    if (path.empty())
    {
        AppendLog(logs, "> No folder path available.");
        return;
    }

    if (!DirectoryExists(path))
    {
        AppendLog(logs, "> Not a directory (won't open): " + path);
        return;
    }

    // Prefer explorer.exe to reliably open directories even if file associations are odd.
    const std::string args = "/e,\"" + path + "\"";
    AppendLog(logs, "> Opening folder: " + path);
    HINSTANCE res = ShellExecuteA(nullptr, "open", "explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
    if ((INT_PTR)res <= 32)
        AppendLog(logs, "> Failed to open folder: " + path);
}

static std::string GetSafeLogsDir()
{
    return GetLocalAppData() + "\\StereoInstallerSafe\\logs";
}

static std::string GetRoamingAppData()
{
    char buf[MAX_PATH]{};
    DWORD len = GetEnvironmentVariableA("APPDATA", buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return {};
    return std::string(buf);
}

static std::string FindBetterDiscordPluginsDir()
{
    // Typical BetterDiscord location:
    // %APPDATA%\BetterDiscord\plugins
    const std::string roaming = GetRoamingAppData();
    if (roaming.empty()) return {};

    const std::string plugins = roaming + "\\BetterDiscord\\plugins";
    if (DirectoryExists(plugins)) return plugins;

    return {};
}

static bool IsBetterDiscordInstalled()
{
    // "Installed" is not enough. Discord updates can leave %APPDATA%\BetterDiscord behind,
    // but BetterDiscord is not active until it patches the currently-installed Discord app.
    //
    // BetterDiscord v1.3+ injects into:
    //   <LocalAppData>\Discord\app-<ver>\modules\discord_desktop_core-*\discord_desktop_core

    const std::string roaming = GetRoamingAppData();
    if (roaming.empty()) return false;

    const std::string bdBase = roaming + "\\BetterDiscord";
    if (!DirectoryExists(bdBase))
        return false;

    const std::string lad = GetLocalAppData();

    const char* variants[] = { "Discord", "DiscordPTB", "DiscordCanary" };
    for (const char* v : variants)
    {
        const std::string base = lad + "\\" + v;
        if (!DirectoryExists(base))
            continue;

        const std::string appDir = FindLatestAppDir(base);
        if (appDir.empty())
            continue;

        const std::string modules = appDir + "\\modules";
        if (!DirectoryExists(modules))
            continue;

        auto coreMods = FindDirectoriesMatching(modules, "discord_desktop_core-*");
        for (const auto& coreMod : coreMods)
        {
            const std::string coreDir = coreMod + "\\discord_desktop_core";
            if (!DirectoryExists(coreDir))
                continue;

            // Marker candidates.
            // Your folder listing shows BD modifies discord_desktop_core\index.js (timestamp changes)
            // but does not necessarily drop a standalone betterdiscord.asar file in this folder.
            // So the most reliable marker is: index.js contains BetterDiscord shim code.

            const std::string indexJs = coreDir + "\\index.js";
            if (FileExists(indexJs))
            {
                std::ifstream in(indexJs, std::ios::binary);
                if (in.is_open())
                {
                    std::string content;
                    in.seekg(0, std::ios::end);
                    const std::streamoff sz = in.tellg();
                    in.seekg(0, std::ios::beg);
                    if (sz > 0 && sz < 1024 * 1024)
                    {
                        content.resize((size_t)sz);
                        in.read(&content[0], (std::streamsize)sz);

                        auto containsAny = [&](const char* a, const char* b, const char* c) {
                            return (content.find(a) != std::string::npos) ||
                                (content.find(b) != std::string::npos) ||
                                (content.find(c) != std::string::npos);
                        };

                        // Common shim identifiers across BD versions.
                        if (containsAny("BetterDiscord", "betterdiscord", "bd_shim"))
                            return true;

                        // Some shims just require/resolve from the roaming BD folder.
                        const std::string roaming = GetRoamingAppData();
                        if (!roaming.empty() && content.find(roaming + "\\\\BetterDiscord") != std::string::npos)
                            return true;
                    }
                }
            }
        }
    }

    return false;
}

static void OpenUrlInBrowser(const std::string& url, std::vector<std::string>& logs)
{
    if (url.empty()) return;
    AppendLog(logs, "> Opening: " + url);
    HINSTANCE res = ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    if ((INT_PTR)res <= 32)
        AppendLog(logs, "> Failed to open URL.");
}

static std::string Sha256Hex(const void* data, size_t size)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return {};

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return {};
    }

    if (!CryptHashData(hHash, (const BYTE*)data, (DWORD)size, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    BYTE hash[32];
    DWORD hashLen = (DWORD)sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (DWORD i = 0; i < hashLen; i++)
    {
        out.push_back(hex[(hash[i] >> 4) & 0xF]);
        out.push_back(hex[hash[i] & 0xF]);
    }
    return out;
}

static std::string Sha256FileHex(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return {};

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return {};
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return {};
    }

    char buf[1024 * 1024];
    while (in)
    {
        in.read(buf, sizeof(buf));
        std::streamsize n = in.gcount();
        if (n > 0)
        {
            if (!CryptHashData(hHash, (const BYTE*)buf, (DWORD)n, 0))
            {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return {};
            }
        }
    }

    BYTE hash[32];
    DWORD hashLen = (DWORD)sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (DWORD i = 0; i < hashLen; i++)
    {
        out.push_back(hex[(hash[i] >> 4) & 0xF]);
        out.push_back(hex[hash[i] & 0xF]);
    }
    return out;
}

static void WriteDiagnosticsReport(const DetectedDiscordInfo& detected, const std::string& bdPlugins, std::vector<std::string>& logs)
{
    const std::string base = GetLocalAppData() + "\\StereoInstallerSafe";
    const std::string logDir = GetSafeLogsDir();
    EnsureDirExists(base);
    EnsureDirExists(logDir);

    SYSTEMTIME st{};
    GetLocalTime(&st);

    std::ostringstream path;
    path << logDir << "\\diagnostics-" << st.wYear
        << "-" << st.wMonth
        << "-" << st.wDay
        << "_" << st.wHour
        << "-" << st.wMinute
        << "-" << st.wSecond
        << ".txt";

    std::ofstream out(path.str(), std::ios::binary);
    if (!out.is_open())
    {
        AppendLog(logs, "> ERROR: failed to write diagnostics report.");
        return;
    }

    out << "StereoInstallerSafe diagnostics\r\n";
    out << "Timestamp: " << st.wYear << "-" << st.wMonth << "-" << st.wDay << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "\r\n\r\n";

    out << "Detected voice module directories:\r\n";
    out << "  Stable: " << detected.stableVoiceDir << "\r\n";
    out << "  PTB:    " << detected.ptbVoiceDir << "\r\n";
    out << "  Canary: " << detected.canaryVoiceDir << "\r\n\r\n";

    out << "BetterDiscord plugins dir:\r\n";
    out << "  " << bdPlugins << "\r\n\r\n";

    auto hashIf = [&](const std::string& dir, const char* file){
        if (dir.empty()) return std::string();
        const std::string p = dir + "\\" + file;
        if (!FileExists(p)) return std::string();
        return Sha256FileHex(p);
    };

    out << "Hashes (SHA-256) if files exist:\r\n";
    out << "  Stable discord_voice.node: " << hashIf(detected.stableVoiceDir, "discord_voice.node") << "\r\n";
    out << "  PTB    discord_voice.node: " << hashIf(detected.ptbVoiceDir, "discord_voice.node") << "\r\n";
    out << "  Canary discord_voice.node: " << hashIf(detected.canaryVoiceDir, "discord_voice.node") << "\r\n";

    out.close();

    AppendLog(logs, "> Wrote diagnostics: " + path.str());
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int)
{
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    // Pull the icon from app.rc (IDI_APP_ICON).
    HICON hIconLarge = (HICON)LoadImageW(hInst, L"IDI_APP_ICON", IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR);
    HICON hIconSmall = (HICON)LoadImageW(hInst, L"IDI_APP_ICON", IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, hInst, hIconLarge, nullptr, nullptr, nullptr, L"StereoInstallerSafe", hIconSmall };
    RegisterClassExW(&wc);

    HWND hwnd = CreateWindowW(wc.lpszClassName, L"Jibi Stereo", WS_OVERLAPPEDWINDOW,
        100, 100, 720, 420, nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();

    // Font: avoid scaling (causes blur). Prefer a crisp system font if available.
    io.Fonts->Clear();
    ImFont* font = nullptr;
    font = io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/segoeui.ttf", 14.0f);
    if (!font)
        font = io.Fonts->AddFontDefault();
    io.FontDefault = font;

    ApplyModernStyle();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    bool done = false;

    std::vector<std::string> logs;
    DetectedDiscordInfo detected{};
    AppendLog(logs, "Welcome! Click Detect to find your Discord folders.");

    DiscordRunState lastRunState = DiscordRunState::NotRunning;
    DWORD lastRunStatePoll = 0;

    while (!done)
    {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        ImGuiViewport* vp = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(vp->WorkPos, ImGuiCond_Always);
        ImGui::SetNextWindowSize(vp->WorkSize, ImGuiCond_Always);

        ImGui::Begin("Jibi Stereo", nullptr,
            ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoBringToFrontOnFocus);

        // Poll running status ~1x/sec without spamming
        const DWORD now = GetTickCount();
        if (now - lastRunStatePoll > 1000)
        {
            lastRunStatePoll = now;
            DiscordRunState cur = GetDiscordRunState();
            if (cur != lastRunState)
            {
                lastRunState = cur;
                if (cur == DiscordRunState::NotRunning)
                    AppendLog(logs, "Discord is closed.");
                else if (cur == DiscordRunState::Stable)
                    AppendLog(logs, "Discord is open.");
                else if (cur == DiscordRunState::PTB)
                    AppendLog(logs, "Discord is open.");
                else if (cur == DiscordRunState::Canary)
                    AppendLog(logs, "Discord is open.");
            }
        }

        const bool discordRunning = (lastRunState != DiscordRunState::NotRunning);
        const ImVec4 ok = ImVec4(0.35f, 0.85f, 0.55f, 1.0f);
        const ImVec4 bad = ImVec4(0.95f, 0.35f, 0.35f, 1.0f);

        ImGui::TextUnformatted("Jibi Stereo");
        ImGui::SameLine();
        ImGui::TextDisabled("(read-only)");

        ImGui::SameLine();
        ImGui::Dummy(ImVec2(10, 0));
        ImGui::SameLine();
        ImGui::TextColored(discordRunning ? bad : ok, "●");
        ImGui::SameLine();
        if (discordRunning)
            ImGui::TextColored(bad, "Discord is running - please close it");
        else
            ImGui::TextColored(ok, "Discord is closed - you may proceed");

        // BetterDiscord status indicator
        const bool bdInstalled = IsBetterDiscordInstalled();
        ImGui::SameLine();
        ImGui::Dummy(ImVec2(14, 0));
        ImGui::SameLine();
        ImGui::TextColored(bdInstalled ? ok : bad, "●");
        ImGui::SameLine();
        if (bdInstalled)
            ImGui::TextColored(ok, "BetterDiscord detected");
        else
            ImGui::TextColored(bad, "BetterDiscord not detected");

        ImGui::Spacing();
        ImGui::TextWrapped("Find Discord voice module folders and your BetterDiscord plugins folder, then follow your setup steps to get stereo audio in Discord.");

        // If BetterDiscord is missing, show a clear call-to-action.
        {
            const bool bdInstalled = IsBetterDiscordInstalled();
            if (!bdInstalled)
            {
                ImGui::Spacing();
                ImGui::PushStyleColor(ImGuiCol_Text, bad);
                ImGui::TextWrapped("BetterDiscord is required to use the stereo plugin. Please install BetterDiscord first.");
                ImGui::PopStyleColor();

                if (ImGui::Button("Install BetterDiscord", ImVec2(180, 0)))
                    OpenUrlInBrowser("https://betterdiscord.app/", logs);

                ImGui::SameLine();
                ImGui::TextDisabled("(opens website)");
            }
        }

        ImGui::Separator();

        // Actions
        ImGui::TextDisabled("Actions");
        if (ImGui::Button("Detect", ImVec2(120, 0)))
        {
            DetectDiscordInstalls(logs, detected);

            // Extra visibility for BetterDiscord detection issues
            AppendLog(logs, std::string("BetterDiscord status: ") + (IsBetterDiscordInstalled() ? "DETECTED" : "NOT DETECTED"));
            AppendLog(logs, "Expected injection location: %LOCALAPPDATA%\\Discord\\app-*\\modules\\discord_desktop_core-*\\discord_desktop_core");
        }

        ImGui::SameLine();
        if (ImGui::Button("Voice", ImVec2(120, 0)))
        {
            if (!detected.stableVoiceDir.empty() && DirectoryExists(detected.stableVoiceDir))
                OpenFolderInExplorer(detected.stableVoiceDir, logs);
            else
                AppendLog(logs, "Click Detect first.");
        }

        ImGui::SameLine();
        if (ImGui::Button("BD Plugins", ImVec2(120, 0)))
        {
            if (!IsBetterDiscordInstalled())
            {
                AppendLog(logs, "BetterDiscord not detected. Install it first: https://betterdiscord.app/");
            }
            else
            {
                const std::string bd = FindBetterDiscordPluginsDir();
                if (bd.empty()) AppendLog(logs, "BetterDiscord plugins folder not found.");
                else OpenFolderInExplorer(bd, logs);
            }
        }

        ImGui::SameLine();
        if (ImGui::Button("Logs", ImVec2(120, 0)))
        {
            const std::string logsDir = GetSafeLogsDir();
            EnsureDirExists(GetLocalAppData() + "\\StereoInstallerSafe");
            EnsureDirExists(logsDir);
            OpenFolderInExplorer(logsDir, logs);
        }

        ImGui::Spacing();

        if (ImGui::Button("Diagnostics", ImVec2(120, 0)))
        {
            const std::string bd = FindBetterDiscordPluginsDir();
            WriteDiagnosticsReport(detected, bd, logs);
        }

        ImGui::SameLine();
        if (ImGui::Button("Clear", ImVec2(120, 0)))
            logs.clear();

        ImGui::Separator();

        ImGui::TextDisabled("Output log");
        ImGui::BeginChild("log", ImVec2(0, 0), true);

        const ImVec4 violet = ImVec4(0.80f, 0.55f, 1.00f, 1.0f);
        const ImVec4 dim = ImVec4(0.70f, 0.70f, 0.78f, 1.0f);

        for (const auto& line : logs)
        {
            // Colorize a few common message types to make the log easier to scan.
            if (line.rfind("> Discord status:", 0) == 0)
                ImGui::TextColored(violet, "%s", line.c_str());
            else if (line.rfind("> Detecting", 0) == 0 || line.rfind("> Done", 0) == 0)
                ImGui::TextColored(dim, "%s", line.c_str());
            else
                ImGui::TextUnformatted(line.c_str());
        }

        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
        ImGui::EndChild();

        ImGui::End();

        ImGui::Render();
        const float clear_color_with_alpha[4] = { 0.10f, 0.10f, 0.12f, 1.00f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}
