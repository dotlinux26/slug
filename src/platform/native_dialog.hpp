#pragma once

#include <string>
#include <filesystem>
#include <thread>
#include "src/core/logger.hpp"

#if defined(_WIN32) || defined(_WIN64)
#  ifndef SLUG_PLATFORM_WINDOWS
#    define SLUG_PLATFORM_WINDOWS 1
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <ole2.h>
#  include <shobjidl.h>
#  include <shellapi.h>
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
#  ifndef SLUG_PLATFORM_POSIX
#    define SLUG_PLATFORM_POSIX 1
#  endif
#  include <cstdio>
#  include <cstdlib>
#endif

namespace slug::platform {

class NativeDialog {
public:
    static std::string pick_folder_native([[maybe_unused]] const std::wstring& title = L"Slug: Chọn Thư Mục", const std::string& posix_title = "Slug: Chọn Thư Mục") {
#if defined(SLUG_PLATFORM_WINDOWS)
        std::string result = "";
        std::thread t([&]() {
            try {
                HRESULT hr = OleInitialize(NULL);
                bool need_uninit = SUCCEEDED(hr);

                IFileOpenDialog* pFileOpen = nullptr;
                hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
                if (SUCCEEDED(hr)) {
                    DWORD dwOptions = 0;
                    if (SUCCEEDED(pFileOpen->GetOptions(&dwOptions))) {
                        pFileOpen->SetOptions(dwOptions | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
                    }
                    pFileOpen->SetTitle(title.c_str());
                    HWND hwndOwner = GetForegroundWindow();
                    if (!hwndOwner) hwndOwner = GetActiveWindow();
                    if (hwndOwner) {
                        SetForegroundWindow(hwndOwner);
                        BringWindowToTop(hwndOwner);
                    }
                    hr = pFileOpen->Show(hwndOwner);
                    if (SUCCEEDED(hr)) {
                        IShellItem* pItem = nullptr;
                        hr = pFileOpen->GetResult(&pItem);
                        if (SUCCEEDED(hr)) {
                            PWSTR pszFilePath = nullptr;
                            hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                            if (SUCCEEDED(hr)) {
                                int size_needed = WideCharToMultiByte(CP_UTF8, 0, pszFilePath, -1, NULL, 0, NULL, NULL);
                                if (size_needed > 0) {
                                    result.resize(size_needed - 1);
                                    WideCharToMultiByte(CP_UTF8, 0, pszFilePath, -1, &result[0], size_needed, NULL, NULL);
                                }
                                CoTaskMemFree(pszFilePath);
                            }
                            pItem->Release();
                        }
                    }
                    pFileOpen->Release();
                } else {
                    SLUG_LOG_ERROR("NativeDialog::pick_folder_native CoCreateInstance failed hr=0x" << std::hex << hr);
                }
                if (need_uninit) OleUninitialize();
            } catch (const std::exception& e) {
                SLUG_LOG_ERROR("NativeDialog::pick_folder_native exception: " << e.what());
            } catch (...) {
                SLUG_LOG_ERROR("NativeDialog::pick_folder_native unknown exception");
            }
        });
        if (t.joinable()) t.join();
        return result;
#elif defined(SLUG_PLATFORM_POSIX)
        std::string chosen_path = "";
        // 1. Zenity modal
        std::string cmd = "zenity --file-selection --directory --title='" + posix_title + "' --modal 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buf[512];
            while (fgets(buf, sizeof(buf), pipe)) {
                chosen_path += buf;
            }
            pclose(pipe);
        }
        // 2. Fallback to kdialog
        if (chosen_path.empty()) {
            std::string kcmd = "kdialog --getexistingdirectory . --title '" + posix_title + "' 2>/dev/null";
            pipe = popen(kcmd.c_str(), "r");
            if (pipe) {
                char buf[512];
                while (fgets(buf, sizeof(buf), pipe)) {
                    chosen_path += buf;
                }
                pclose(pipe);
            }
        }
        while (!chosen_path.empty() && (chosen_path.back() == '\r' || chosen_path.back() == '\n')) {
            chosen_path.pop_back();
        }
        return chosen_path;
#else
        return "";
#endif
    }

    static std::string pick_file_native([[maybe_unused]] const std::wstring& title = L"Slug: Chọn Tệp Tin") {
#if defined(SLUG_PLATFORM_WINDOWS)
        std::string result = "";
        std::thread t([&]() {
            try {
                HRESULT hr = OleInitialize(NULL);
                bool need_uninit = SUCCEEDED(hr);

                IFileOpenDialog* pFileOpen = nullptr;
                hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, IID_IFileOpenDialog, reinterpret_cast<void**>(&pFileOpen));
                if (SUCCEEDED(hr)) {
                    DWORD dwOptions = 0;
                    if (SUCCEEDED(pFileOpen->GetOptions(&dwOptions))) {
                        pFileOpen->SetOptions(dwOptions | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST);
                    }
                    pFileOpen->SetTitle(title.c_str());
                    HWND hwndOwner = GetForegroundWindow();
                    if (!hwndOwner) hwndOwner = GetActiveWindow();
                    if (hwndOwner) {
                        SetForegroundWindow(hwndOwner);
                        BringWindowToTop(hwndOwner);
                    }
                    hr = pFileOpen->Show(hwndOwner);
                    if (SUCCEEDED(hr)) {
                        IShellItem* pItem = nullptr;
                        hr = pFileOpen->GetResult(&pItem);
                        if (SUCCEEDED(hr)) {
                            PWSTR pszFilePath = nullptr;
                            hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                            if (SUCCEEDED(hr)) {
                                int size_needed = WideCharToMultiByte(CP_UTF8, 0, pszFilePath, -1, NULL, 0, NULL, NULL);
                                if (size_needed > 0) {
                                    result.resize(size_needed - 1);
                                    WideCharToMultiByte(CP_UTF8, 0, pszFilePath, -1, &result[0], size_needed, NULL, NULL);
                                }
                                CoTaskMemFree(pszFilePath);
                            }
                            pItem->Release();
                        }
                    }
                    pFileOpen->Release();
                } else {
                    SLUG_LOG_ERROR("NativeDialog::pick_file_native CoCreateInstance failed hr=0x" << std::hex << hr);
                }
                if (need_uninit) OleUninitialize();
            } catch (const std::exception& e) {
                SLUG_LOG_ERROR("NativeDialog::pick_file_native exception: " << e.what());
            } catch (...) {
                SLUG_LOG_ERROR("NativeDialog::pick_file_native unknown exception");
            }
        });
        if (t.joinable()) t.join();
        return result;
#elif defined(SLUG_PLATFORM_POSIX)
        std::string chosen_path = "";
        FILE* pipe = popen("zenity --file-selection --title='Slug: Chọn Tệp Tin' --modal 2>/dev/null", "r");
        if (pipe) {
            char buf[512];
            while (fgets(buf, sizeof(buf), pipe)) {
                chosen_path += buf;
            }
            pclose(pipe);
        }
        if (chosen_path.empty()) {
            pipe = popen("kdialog --getopenfilename . --title 'Slug: Chọn Tệp Tin' 2>/dev/null", "r");
            if (pipe) {
                char buf[512];
                while (fgets(buf, sizeof(buf), pipe)) {
                    chosen_path += buf;
                }
                pclose(pipe);
            }
        }
        while (!chosen_path.empty() && (chosen_path.back() == '\r' || chosen_path.back() == '\n')) {
            chosen_path.pop_back();
        }
        return chosen_path;
#else
        return "";
#endif
    }

    static std::string save_file_native([[maybe_unused]] const std::string& default_filename, [[maybe_unused]] const std::wstring& title = L"Slug: Chọn Nơi Lưu Tệp Tin") {
#if defined(SLUG_PLATFORM_WINDOWS)
        std::string result = "";
        std::thread t([&]() {
            try {
                HRESULT hr = OleInitialize(NULL);
                bool need_uninit = SUCCEEDED(hr);

                IFileSaveDialog* pFileSave = nullptr;
                hr = CoCreateInstance(CLSID_FileSaveDialog, NULL, CLSCTX_INPROC_SERVER, IID_IFileSaveDialog, reinterpret_cast<void**>(&pFileSave));
                if (SUCCEEDED(hr)) {
                    DWORD dwOptions = 0;
                    if (SUCCEEDED(pFileSave->GetOptions(&dwOptions))) {
                        pFileSave->SetOptions(dwOptions | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT);
                    }
                    pFileSave->SetTitle(title.c_str());
                    if (!default_filename.empty()) {
                        int wlen = MultiByteToWideChar(CP_UTF8, 0, default_filename.c_str(), -1, NULL, 0);
                        if (wlen > 0) {
                            std::wstring wname(wlen - 1, L'\0');
                            MultiByteToWideChar(CP_UTF8, 0, default_filename.c_str(), -1, &wname[0], wlen);
                            pFileSave->SetFileName(wname.c_str());
                        }
                    }
                    HWND hwndOwner = GetForegroundWindow();
                    if (!hwndOwner) hwndOwner = GetActiveWindow();
                    if (hwndOwner) {
                        SetForegroundWindow(hwndOwner);
                        BringWindowToTop(hwndOwner);
                    }
                    hr = pFileSave->Show(hwndOwner);
                    if (SUCCEEDED(hr)) {
                        IShellItem* pItem = nullptr;
                        hr = pFileSave->GetResult(&pItem);
                        if (SUCCEEDED(hr)) {
                            PWSTR pszFilePath = nullptr;
                            hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                            if (SUCCEEDED(hr)) {
                                int size_needed = WideCharToMultiByte(CP_UTF8, 0, pszFilePath, -1, NULL, 0, NULL, NULL);
                                if (size_needed > 0) {
                                    result.resize(size_needed - 1);
                                    WideCharToMultiByte(CP_UTF8, 0, pszFilePath, -1, &result[0], size_needed, NULL, NULL);
                                }
                                CoTaskMemFree(pszFilePath);
                            }
                            pItem->Release();
                        }
                    }
                    pFileSave->Release();
                } else {
                    SLUG_LOG_ERROR("NativeDialog::save_file_native CoCreateInstance failed hr=0x" << std::hex << hr);
                }
                if (need_uninit) OleUninitialize();
            } catch (const std::exception& e) {
                SLUG_LOG_ERROR("NativeDialog::save_file_native exception: " << e.what());
            } catch (...) {
                SLUG_LOG_ERROR("NativeDialog::save_file_native unknown exception");
            }
        });
        if (t.joinable()) t.join();
        return result;
#elif defined(SLUG_PLATFORM_POSIX)
        std::string chosen_path = "";
        std::string cmd = "zenity --file-selection --save --confirm-overwrite --title='Slug: Chọn Nơi Lưu Tệp Tin'";
        if (!default_filename.empty()) {
            cmd += " --filename='" + default_filename + "'";
        }
        cmd += " --modal 2>/dev/null";
        FILE* pipe = popen(cmd.c_str(), "r");
        if (pipe) {
            char buf[512];
            while (fgets(buf, sizeof(buf), pipe)) {
                chosen_path += buf;
            }
            pclose(pipe);
        }
        if (chosen_path.empty()) {
            std::string kcmd = "kdialog --getsavefilename . --title 'Slug: Chọn Nơi Lưu Tệp Tin' 2>/dev/null";
            pipe = popen(kcmd.c_str(), "r");
            if (pipe) {
                char buf[512];
                while (fgets(buf, sizeof(buf), pipe)) {
                    chosen_path += buf;
                }
                pclose(pipe);
            }
        }
        while (!chosen_path.empty() && (chosen_path.back() == '\r' || chosen_path.back() == '\n')) {
            chosen_path.pop_back();
        }
        return chosen_path;
#else
        return "";
#endif
    }

    static bool open_path_in_os(const std::string& path_str) {
        if (path_str.empty()) return false;
        try {
#if defined(SLUG_PLATFORM_WINDOWS)
            int wlen = MultiByteToWideChar(CP_UTF8, 0, path_str.c_str(), -1, NULL, 0);
            std::wstring wpath;
            if (wlen > 0) {
                wpath.resize(wlen - 1);
                MultiByteToWideChar(CP_UTF8, 0, path_str.c_str(), -1, &wpath[0], wlen);
            } else {
                wpath.assign(path_str.begin(), path_str.end());
            }
            std::filesystem::path p(wpath);
            std::error_code ec;
            if (!std::filesystem::exists(p, ec)) {
                p = std::filesystem::absolute(p, ec);
            }
            std::wstring native_w = p.make_preferred().wstring();
            HWND hwnd_owner = GetForegroundWindow();
            if (!hwnd_owner) hwnd_owner = GetDesktopWindow();
            AllowSetForegroundWindow(ASFW_ANY);
            HINSTANCE res = ShellExecuteW(hwnd_owner, L"explore", native_w.c_str(), NULL, NULL, SW_SHOWNORMAL);
            if (reinterpret_cast<INT_PTR>(res) <= 32) {
                res = ShellExecuteW(hwnd_owner, L"open", native_w.c_str(), NULL, NULL, SW_SHOWNORMAL);
            }
            return reinterpret_cast<INT_PTR>(res) > 32;
#elif defined(SLUG_PLATFORM_POSIX)
            std::filesystem::path p(path_str);
            std::error_code ec;
            if (!std::filesystem::exists(p, ec)) {
                p = std::filesystem::absolute(p, ec);
            }
            std::string native_p = p.make_preferred().string();
            std::string cmd = "xdg-open \"" + native_p + "\" >/dev/null 2>&1 &";
            int ret = system(cmd.c_str());
            return ret == 0;
#else
            return false;
#endif
        } catch (...) {
            return false;
        }
    }
};

} // namespace slug::platform
