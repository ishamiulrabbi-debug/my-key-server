#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <bcrypt.h>
#include <wincrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

// Typedefs for original WinHttp functions
typedef HINTERNET (WINAPI* PROTO_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI* PROTO_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI* PROTO_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI* PROTO_WinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL (WINAPI* PROTO_WinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL (WINAPI* PROTO_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI* PROTO_WinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef WINHTTP_STATUS_CALLBACK (WINAPI* PROTO_WinHttpSetStatusCallback)(HINTERNET, WINHTTP_STATUS_CALLBACK, DWORD, DWORD_PTR);

// Trampolines/Original function pointers
PROTO_WinHttpConnect Orig_WinHttpConnect = NULL;
PROTO_WinHttpOpenRequest Orig_WinHttpOpenRequest = NULL;
PROTO_WinHttpSendRequest Orig_WinHttpSendRequest = NULL;
PROTO_WinHttpReceiveResponse Orig_WinHttpReceiveResponse = NULL;
PROTO_WinHttpQueryDataAvailable Orig_WinHttpQueryDataAvailable = NULL;
PROTO_WinHttpReadData Orig_WinHttpReadData = NULL;
PROTO_WinHttpQueryHeaders Orig_WinHttpQueryHeaders = NULL;
PROTO_WinHttpSetStatusCallback Orig_WinHttpSetStatusCallback = NULL;

typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS (NTAPI* PROTO_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);
extern PROTO_NtProtectVirtualMemory Orig_NtProtectVirtualMemory;

// Base64 helper functions using Windows Crypt32 API
std::string Base64Encode(const std::vector<BYTE>& data) {
    DWORD size = 0;
    CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size);
    std::string str(size, '\0');
    CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &str[0], &size);
    while (!str.empty() && (str.back() == '\0' || str.back() == '\r' || str.back() == '\n')) {
        str.pop_back();
    }
    return str;
}

std::vector<BYTE> Base64Decode(const std::string& b64) {
    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), b64.length(), CRYPT_STRING_BASE64, NULL, &size, NULL, NULL);
    std::vector<BYTE> buf(size);
    CryptStringToBinaryA(b64.c_str(), b64.length(), CRYPT_STRING_BASE64, buf.data(), &size, NULL, NULL);
    return buf;
}

// URL Decode helper
std::string UrlDecode(const std::string& str) {
    std::string res;
    for (size_t i = 0; i < str.length(); i++) {
        if (str[i] == '%' && i + 2 < str.length()) {
            char hex[3] = { str[i+1], str[i+2], '\0' };
            res += (char)strtol(hex, NULL, 16);
            i += 2;
        } else if (str[i] == '+') {
            res += ' ';
        } else {
            res += str[i];
        }
    }
    return res;
}

// SHA256 helper using BCrypt
std::string CalculateSHA256(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbHashObject = 0, cbHash = 0, cbData = 0;
    
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0);
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    
    std::vector<BYTE> hashObject(cbHashObject);
    std::vector<BYTE> hash(cbHash);
    
    BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, NULL, 0, 0);
    BCryptHashData(hHash, (PBYTE)input.c_str(), input.length(), 0);
    BCryptFinishHash(hHash, hash.data(), cbHash, 0);
    
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    char hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf_s(hex + i*2, 3, "%02x", hash[i]);
    }
    return std::string(hex);
}

// Hex decoder
std::vector<BYTE> HexDecode(const std::string& hex) {
    std::vector<BYTE> bytes(hex.length() / 2);
    for (size_t i = 0; i < bytes.size(); i++) {
        std::string byteString = hex.substr(i * 2, 2);
        bytes[i] = (BYTE)strtol(byteString.c_str(), NULL, 16);
    }
    return bytes;
}

// AES-256-CBC Decryption using BCrypt
std::vector<BYTE> AES256Decrypt(const std::vector<BYTE>& ciphertext, const std::vector<BYTE>& key, const std::vector<BYTE>& iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    
    DWORD cbKeyObject = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    
    std::vector<BYTE> keyObject(cbKeyObject);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), cbKeyObject, (PBYTE)key.data(), key.size(), 0);
    
    std::vector<BYTE> ivCopy = iv;
    DWORD cbPlainText = 0;
    BCryptDecrypt(hKey, (PBYTE)ciphertext.data(), ciphertext.size(), NULL, ivCopy.data(), ivCopy.size(), NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    
    std::vector<BYTE> plaintext(cbPlainText);
    BCryptDecrypt(hKey, (PBYTE)ciphertext.data(), ciphertext.size(), NULL, ivCopy.data(), ivCopy.size(), plaintext.data(), cbPlainText, &cbPlainText, BCRYPT_BLOCK_PADDING);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return plaintext;
}

// AES-256-CBC Encryption using BCrypt
std::vector<BYTE> AES256Encrypt(const std::vector<BYTE>& plaintext, const std::vector<BYTE>& key, const std::vector<BYTE>& iv) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    
    DWORD cbKeyObject = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
    
    std::vector<BYTE> keyObject(cbKeyObject);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), cbKeyObject, (PBYTE)key.data(), key.size(), 0);
    
    std::vector<BYTE> ivCopy = iv;
    DWORD cbCipherText = 0;
    BCryptEncrypt(hKey, (PBYTE)plaintext.data(), plaintext.size(), NULL, ivCopy.data(), ivCopy.size(), NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    
    std::vector<BYTE> ciphertext(cbCipherText);
    BCryptEncrypt(hKey, (PBYTE)plaintext.data(), plaintext.size(), NULL, ivCopy.data(), ivCopy.size(), ciphertext.data(), cbCipherText, &cbCipherText, BCRYPT_BLOCK_PADDING);
    
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    
    return ciphertext;
}

// ====================================================================================
// Global Configuration Settings
// ====================================================================================
bool g_onlineMode = false;
std::wstring g_serverIp = L"127.0.0.1";
INTERNET_PORT g_serverPort = 8080;
bool g_useHttps = false;
std::string g_autoLoginKey = "";

std::string GetJsonStringValue(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    
    size_t colon = json.find(":", pos);
    if (colon == std::string::npos) return "";
    
    size_t quoteStart = json.find("\"", colon);
    if (quoteStart == std::string::npos) return "";
    
    size_t quoteEnd = json.find("\"", quoteStart + 1);
    if (quoteEnd == std::string::npos) return "";
    
    return json.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
}

int GetJsonIntValue(const std::string& json, const std::string& key, int defaultValue) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return defaultValue;
    
    size_t colon = json.find(":", pos);
    if (colon == std::string::npos) return defaultValue;
    
    size_t digitStart = json.find_first_of("0123456789", colon);
    if (digitStart == std::string::npos) return defaultValue;
    
    size_t digitEnd = json.find_first_not_of("0123456789", digitStart);
    std::string valStr = (digitEnd == std::string::npos) ? json.substr(digitStart) : json.substr(digitStart, digitEnd - digitStart);
    
    try {
        return std::stoi(valStr);
    } catch (...) {
        return defaultValue;
    }
}

bool GetJsonBoolValue(const std::string& json, const std::string& key, bool defaultValue) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return defaultValue;
    
    size_t colon = json.find(":", pos);
    if (colon == std::string::npos) return defaultValue;
    
    size_t truePos = json.find("true", colon);
    size_t falsePos = json.find("false", colon);
    
    if (truePos != std::string::npos && (falsePos == std::string::npos || truePos < falsePos)) {
        return true;
    }
    if (falsePos != std::string::npos && (truePos == std::string::npos || falsePos < truePos)) {
        return false;
    }
    return defaultValue;
}

std::wstring ToWString(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

void LoadConfiguration() {
    std::ifstream file("config.json");
    if (!file.is_open()) {
        std::cout << "[*] Config: config.json not found. Using default offline mode." << std::endl;
        g_onlineMode = false;
        return;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    std::string mode = GetJsonStringValue(content, "mode");
    g_onlineMode = (mode == "online");
    
    std::string ip = GetJsonStringValue(content, "server_ip");
    if (!ip.empty()) {
        g_serverIp = ToWString(ip);
    }
    
    g_serverPort = (INTERNET_PORT)GetJsonIntValue(content, "server_port", 8080);
    g_useHttps = GetJsonBoolValue(content, "use_https", false);
    g_autoLoginKey = GetJsonStringValue(content, "auto_login_key");
    
    std::cout << "[+] Config loaded successfully:" << std::endl;
    std::cout << "    --> Mode: " << (g_onlineMode ? "online" : "offline") << std::endl;
    if (g_onlineMode) {
        std::wcout << L"    --> Server IP/Domain: " << g_serverIp << std::endl;
        std::cout << "    --> Server Port: " << g_serverPort << std::endl;
        std::cout << "    --> SSL (HTTPS): " << (g_useHttps ? "enabled" : "disabled") << std::endl;
    }
    if (!g_autoLoginKey.empty()) {
        std::cout << "    --> Auto-Login Key: '" << g_autoLoginKey << "'" << std::endl;
    } else {
        std::cout << "    --> Auto-Login Key: [disabled - prompting user]" << std::endl;
    }
}

void ClearPersistedKey() {
    if (g_autoLoginKey.empty()) {
        HKEY hKey;
        LONG status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            L"Software\\BRMods\\Launcher",
            0,
            KEY_SET_VALUE,
            &hKey
        );
        if (status == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, L"ServerKeyDpapiV1");
            RegCloseKey(hKey);
            std::cout << "[+] Auto-Bypass: Cleared saved registry key to show Login UI." << std::endl;
        }
    } else {
        DATA_BLOB dataIn;
        dataIn.pbData = (BYTE*)g_autoLoginKey.c_str();
        dataIn.cbData = g_autoLoginKey.length();
        
        DATA_BLOB dataOut;
        if (CryptProtectData(&dataIn, L"ServerKey", NULL, NULL, NULL, 0, &dataOut)) {
            HKEY hKey;
            LONG status = RegCreateKeyExW(
                HKEY_CURRENT_USER,
                L"Software\\BRMods\\Launcher",
                0,
                NULL,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                NULL,
                &hKey,
                NULL
            );
            if (status == ERROR_SUCCESS) {
                RegSetValueExW(hKey, L"ServerKeyDpapiV1", 0, REG_BINARY, dataOut.pbData, dataOut.cbData);
                RegCloseKey(hKey);
                std::cout << "[+] Auto-Bypass: Stored DPAPI-encrypted key in registry!" << std::endl;
            }
            LocalFree(dataOut.pbData);
        }
    }
}

// Global dynamically generated mock JSON response
std::string g_dynamicMockResponse = "";

// Dynamic response builder
std::string GenerateEncryptedResponse(const std::string& rawPostBody) {
    // Parse iv and payload from post body
    std::string b64_iv = "";
    std::string b64_payload = "";
    
    size_t iv_pos = rawPostBody.find("iv=");
    if (iv_pos != std::string::npos) {
        size_t end = rawPostBody.find('&', iv_pos);
        std::string encoded = rawPostBody.substr(iv_pos + 3, (end == std::string::npos) ? std::string::npos : end - (iv_pos + 3));
        b64_iv = UrlDecode(encoded);
    }
    
    size_t payload_pos = rawPostBody.find("payload=");
    if (payload_pos != std::string::npos) {
        size_t end = rawPostBody.find('&', payload_pos);
        std::string encoded = rawPostBody.substr(payload_pos + 8, (end == std::string::npos) ? std::string::npos : end - (payload_pos + 8));
        b64_payload = UrlDecode(encoded);
    }
    
    if (b64_iv.empty() || b64_payload.empty()) {
        std::cout << "[-] Error: Missing iv or payload in request body!" << std::endl;
        return "";
    }
    
    std::vector<BYTE> iv = Base64Decode(b64_iv);
    std::vector<BYTE> payload = Base64Decode(b64_payload);
    
    // Decrypt client request payload
    std::string request_key_hex = "d7659c1e7e7701e2286a351a15e0c0c14258d752a9f4c0f66713c5febc337c1c";
    std::vector<BYTE> req_key = HexDecode(request_key_hex);
    
    std::vector<BYTE> decrypted = AES256Decrypt(payload, req_key, iv);
    std::string dec_str((char*)decrypted.data(), decrypted.size());
    std::cout << "[+] Hook: Decrypted Client Request: " << dec_str << std::endl;
    
    // Extract nonce from decrypted payload
    std::string nonce = "";
    size_t nonce_pos = dec_str.find("\"nonce\":\"");
    if (nonce_pos != std::string::npos) {
        nonce = dec_str.substr(nonce_pos + 9, 32);
    }
    
    // Extract key dynamically from decrypted payload
    std::string key_val = "";
    size_t key_pos = dec_str.find("\"key\":\"");
    if (key_pos != std::string::npos) {
        size_t key_end = dec_str.find("\"", key_pos + 7);
        if (key_end != std::string::npos) {
            key_val = dec_str.substr(key_pos + 7, key_end - (key_pos + 7));
        }
    }
    
    if (nonce.empty()) {
        std::cout << "[-] Error: Failed to extract nonce from decrypted request!" << std::endl;
        return "";
    }
    std::cout << "[+] Hook: Extracted Nonce: " << nonce << std::endl;
    std::cout << "[+] Hook: Extracted Client Key: " << key_val << std::endl;
    
    // Response key derivation: derived from the server master key constant + nonce.
    std::string server_master_key = "d732f3d741bbeeca76596132ef8e34f30813d2e03605ff3bbb2a5d2d2b4af9a0";
    std::string key_input = server_master_key + nonce;
    std::string resp_key_hex = CalculateSHA256(key_input);
    std::vector<BYTE> resp_key = HexDecode(resp_key_hex);
    
    // Extract timestamp dynamically from decrypted payload
    std::string ts_val = "";
    size_t ts_pos = dec_str.find("\"ts\"");
    if (ts_pos != std::string::npos) {
        size_t start = ts_pos + 4;
        while (start < dec_str.length() && (dec_str[start] == ' ' || dec_str[start] == '"' || dec_str[start] == ':' || dec_str[start] == '\t')) {
            start++;
        }
        size_t end = start;
        while (end < dec_str.length() && dec_str[end] >= '0' && dec_str[end] <= '9') {
            end++;
        }
        if (end > start) {
            ts_val = dec_str.substr(start, end - start);
        }
    }
    if (ts_val.empty()) {
        ts_val = std::to_string((unsigned long)time(NULL));
    }
    
    // Success JSON payload (aligned with server.py exactly)
    std::string success_json = 
        "{\"status\":\"success\",\"success\":true,\"mensagem\":\"Loaded\","
        "\"token\":\"brmods_bypass_token_2026\",\"product\":\"BRMods\","
        "\"vendedor\":\"ServerKey\",\"dias\":9999,\"timeData\":" + ts_val + ","
        "\"expire\":1918000000,\"o_ga\":\"\",\"o_gf\":\"\",\"o_pn\":\"\",\"o_pugc\":\"\","
        "\"o_pths\":\"\",\"o_pth\":\"\"}";
        
    // Use a constant 16-byte IV for the response
    std::vector<BYTE> resp_iv = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    
    // Convert success_json to vector<BYTE> (padding with block size alignment)
    std::vector<BYTE> plaintext(success_json.begin(), success_json.end());
    plaintext.push_back('\0'); // Safe null terminator to prevent parsing overflows on client side
    std::vector<BYTE> ciphertext = AES256Encrypt(plaintext, resp_key, resp_iv);
    
    // Build final response JSON
    std::string resp_b64_iv = Base64Encode(resp_iv);
    std::string resp_b64_payload = Base64Encode(ciphertext);
    
    std::string final_response = "{\"iv\":\"" + resp_b64_iv + "\",\"payload\":\"" + resp_b64_payload + "\"}";
    std::cout << "[+] Hook: Generated Encrypted Success Response Successfully!" << std::endl;
    return final_response;
}

// Global state for reading mock response
DWORD g_bytesRead = 0;

// Handles tracking to only mock authentication requests
#define MAX_HANDLES 2048
struct HandleMap {
    HINTERNET handle;
    bool isMock;
    bool isRedirected;
    WINHTTP_STATUS_CALLBACK callback;
    DWORD_PTR context;
} g_mockHandles[MAX_HANDLES];
int g_handleCount = 0;
CRITICAL_SECTION g_cs;

void AddMockHandle(HINTERNET h, bool isMock, bool isRedirected = false) {
    EnterCriticalSection(&g_cs);
    if (g_handleCount < MAX_HANDLES) {
        g_mockHandles[g_handleCount++] = { h, isMock, isRedirected, NULL, 0 };
    }
    LeaveCriticalSection(&g_cs);
}

bool IsMockHandle(HINTERNET h) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_handleCount; i++) {
        if (g_mockHandles[i].handle == h) {
            LeaveCriticalSection(&g_cs);
            return g_mockHandles[i].isMock;
        }
    }
    LeaveCriticalSection(&g_cs);
    return false;
}

bool IsRedirectedHandle(HINTERNET h) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_handleCount; i++) {
        if (g_mockHandles[i].handle == h) {
            LeaveCriticalSection(&g_cs);
            return g_mockHandles[i].isRedirected;
        }
    }
    LeaveCriticalSection(&g_cs);
    return false;
}

void SetHandleCallback(HINTERNET h, WINHTTP_STATUS_CALLBACK cb, DWORD_PTR ctx) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_handleCount; i++) {
        if (g_mockHandles[i].handle == h) {
            g_mockHandles[i].callback = cb;
            g_mockHandles[i].context = ctx;
            break;
        }
    }
    LeaveCriticalSection(&g_cs);
}

WINHTTP_STATUS_CALLBACK GetHandleCallback(HINTERNET h, DWORD_PTR* pCtx) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_handleCount; i++) {
        if (g_mockHandles[i].handle == h) {
            if (pCtx) *pCtx = g_mockHandles[i].context;
            WINHTTP_STATUS_CALLBACK cb = g_mockHandles[i].callback;
            LeaveCriticalSection(&g_cs);
            return cb;
        }
    }
    LeaveCriticalSection(&g_cs);
    return NULL;
}

// Hook definitions
#pragma optimize("", off)

HINTERNET WINAPI Hooked_WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved) {
    bool isTarget = false;
    if (pswzServerName) {
        std::wstring server(pswzServerName);
        if (server.find(L"vncheater") != std::wstring::npos || 
            server.find(L"serverkey") != std::wstring::npos ||
            server.find(L"brmods") != std::wstring::npos ||
            server.find(L"auth") != std::wstring::npos) {
            isTarget = true;
        }
    }
    
    if (isTarget) {
        if (g_onlineMode) {
            std::wcout << L"[+] Hook: Redirecting connection to safe server: " << g_serverIp << L":" << g_serverPort << std::endl;
            HINTERNET hConnect = Orig_WinHttpConnect(hSession, g_serverIp.c_str(), g_serverPort, dwReserved);
            if (hConnect) {
                AddMockHandle(hConnect, false, true); // isMock = false, isRedirected = true
            }
            return hConnect;
        } else {
            std::wcout << L"[+] Hook: Mocking connection locally (Offline Mode)." << std::endl;
            HINTERNET hConnect = Orig_WinHttpConnect(hSession, L"127.0.0.1", 8080, dwReserved);
            if (hConnect) {
                AddMockHandle(hConnect, true, false); // isMock = true, isRedirected = false
            }
            return hConnect;
        }
    }
    
    return Orig_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
}

HINTERNET WINAPI Hooked_WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags) {
    bool isMock = IsMockHandle(hConnect);
    bool isRedirected = IsRedirectedHandle(hConnect);
    
    if (isMock && pwszObjectName) {
        std::wcout << L"[+] Hook: Intercepted OpenRequest Path: " << pwszObjectName << std::endl;
    }
    
    DWORD flags = dwFlags;
    if (isRedirected && !g_useHttps) {
        flags &= ~WINHTTP_FLAG_SECURE; // Strip secure flag to use HTTP
        std::cout << "[+] Hook: Stripped WINHTTP_FLAG_SECURE to force HTTP." << std::endl;
    }
    
    HINTERNET hRequest = Orig_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion, pwszReferrer, ppwszAcceptTypes, flags);
    if (hRequest) {
        AddMockHandle(hRequest, IsMockHandle(hConnect), IsRedirectedHandle(hConnect));
    }
    return hRequest;
}

BOOL WINAPI Hooked_WinHttpSendRequest(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext) {
    if (IsMockHandle(hRequest)) {
        std::cout << "[+] Hook: Intercepted auth request Send." << std::endl;
        g_bytesRead = 0; // Reset read index
        
        std::cout << "    --> Headers: ";
        if (pwszHeaders) {
            if (dwHeadersLength == (DWORD)-1) {
                std::wcout << pwszHeaders << std::endl;
            } else if (dwHeadersLength > 0) {
                std::wcout << std::wstring(pwszHeaders, dwHeadersLength) << std::endl;
            } else {
                std::cout << "None" << std::endl;
            }
        } else {
            std::cout << "None" << std::endl;
        }
        std::cout << "    --> Optional Data (len " << dwOptionalLength << "): ";
        std::string postBody = "";
        if (lpOptional && dwOptionalLength > 0) {
            char* data = (char*)lpOptional;
            postBody = std::string(data, dwOptionalLength);
            for (DWORD i = 0; i < dwOptionalLength; i++) {
                char c = data[i];
                if (c >= 32 && c < 127) std::cout << c;
                else std::cout << "\\x" << std::hex << (int)(unsigned char)c << std::dec;
            }
            std::cout << std::endl;
        } else {
            std::cout << "None" << std::endl;
        }

        // Generate the dynamic encrypted response from postBody
        g_dynamicMockResponse = GenerateEncryptedResponse(postBody);

        // Save the context associated with this request handle
        SetHandleCallback(hRequest, GetHandleCallback(hRequest, NULL), dwContext);
        
        // Trigger async callback for SENDREQUEST_COMPLETE if callback exists
        DWORD_PTR ctx = 0;
        WINHTTP_STATUS_CALLBACK cb = GetHandleCallback(hRequest, &ctx);
        if (cb) {
            std::cout << "    --> Invoking callback for SENDREQUEST_COMPLETE" << std::endl;
            cb(hRequest, ctx, WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE, NULL, 0);
        }
        return TRUE;
    }
    return Orig_WinHttpSendRequest(hRequest, pwszHeaders, dwHeadersLength, lpOptional, dwOptionalLength, dwTotalLength, dwContext);
}

BOOL WINAPI Hooked_WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved) {
    if (IsMockHandle(hRequest)) {
        std::cout << "[+] Hook: Intercepted auth request ReceiveResponse." << std::endl;
        
        // Trigger async callback for HEADERS_AVAILABLE if callback exists
        DWORD_PTR ctx = 0;
        WINHTTP_STATUS_CALLBACK cb = GetHandleCallback(hRequest, &ctx);
        if (cb) {
            std::cout << "    --> Invoking callback for HEADERS_AVAILABLE" << std::endl;
            cb(hRequest, ctx, WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE, NULL, 0);
        }
        return TRUE;
    }
    return Orig_WinHttpReceiveResponse(hRequest, lpReserved);
}

BOOL WINAPI Hooked_WinHttpQueryDataAvailable(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable) {
    if (IsMockHandle(hRequest)) {
        DWORD available = g_dynamicMockResponse.length() - g_bytesRead;
        if (lpdwNumberOfBytesAvailable) {
            *lpdwNumberOfBytesAvailable = available;
        }
        
        // Trigger async callback for DATA_AVAILABLE if callback exists
        DWORD_PTR ctx = 0;
        WINHTTP_STATUS_CALLBACK cb = GetHandleCallback(hRequest, &ctx);
        if (cb) {
            std::cout << "    --> Invoking callback for DATA_AVAILABLE" << std::endl;
            DWORD* pBytes = new DWORD(available);
            cb(hRequest, ctx, WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE, pBytes, sizeof(DWORD));
            delete pBytes;
        }
        return TRUE;
    }
    return Orig_WinHttpQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable);
}

BOOL WINAPI Hooked_WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead) {
    if (IsMockHandle(hRequest)) {
        DWORD available = g_dynamicMockResponse.length() - g_bytesRead;
        DWORD toRead = dwNumberOfBytesToRead;
        if (toRead > available) toRead = available;
        
        if (toRead > 0) {
            memcpy(lpBuffer, g_dynamicMockResponse.c_str() + g_bytesRead, toRead);
            g_bytesRead += toRead;
        }
        if (lpdwNumberOfBytesRead) {
            *lpdwNumberOfBytesRead = toRead;
        }
        
        // Trigger async callback for READ_COMPLETE if callback exists
        DWORD_PTR ctx = 0;
        WINHTTP_STATUS_CALLBACK cb = GetHandleCallback(hRequest, &ctx);
        if (cb) {
            std::cout << "    --> Invoking callback for READ_COMPLETE" << std::endl;
            cb(hRequest, ctx, WINHTTP_CALLBACK_STATUS_READ_COMPLETE, lpBuffer, toRead);
        }
        return TRUE;
    }
    return Orig_WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

BOOL WINAPI Hooked_WinHttpQueryHeaders(
    HINTERNET hRequest,
    DWORD dwInfoLevel,
    LPCWSTR pwszName,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    LPDWORD lpdwIndex
) {
    if (IsMockHandle(hRequest)) {
        std::cout << "[+] Hook: Intercepted WinHttpQueryHeaders for InfoLevel: 0x" << std::hex << dwInfoLevel << std::dec << std::endl;
        
        // Check if query is for status code
        if ((dwInfoLevel & 0xFFFF) == WINHTTP_QUERY_STATUS_CODE) {
            if (dwInfoLevel & WINHTTP_QUERY_FLAG_NUMBER) {
                if (lpdwBufferLength) {
                    *lpdwBufferLength = sizeof(DWORD);
                }
                if (lpBuffer) {
                    *(DWORD*)lpBuffer = 200; // HTTP 200 OK
                }
                std::cout << "    --> Returned status code 200 (number)" << std::endl;
                return TRUE;
            } else {
                const wchar_t* statusCodeStr = L"200";
                DWORD len = (wcslen(statusCodeStr) + 1) * sizeof(wchar_t);
                if (lpdwBufferLength) {
                    *lpdwBufferLength = len - sizeof(wchar_t); // Exclude null terminator size
                }
                if (lpBuffer) {
                    wcscpy_s((wchar_t*)lpBuffer, len / sizeof(wchar_t), statusCodeStr);
                }
                std::cout << "    --> Returned status code 200 (string)" << std::endl;
                return TRUE;
            }
        }
        
        // Check if query is for content length
        if ((dwInfoLevel & 0xFFFF) == WINHTTP_QUERY_CONTENT_LENGTH) {
            wchar_t lenStr[32];
            swprintf_s(lenStr, L"%d", (int)(g_dynamicMockResponse.length()));
            DWORD lenBytes = (wcslen(lenStr) + 1) * sizeof(wchar_t);
            if (lpdwBufferLength) {
                *lpdwBufferLength = lenBytes - sizeof(wchar_t);
            }
            if (lpBuffer) {
                wcscpy_s((wchar_t*)lpBuffer, lenBytes / sizeof(wchar_t), lenStr);
            }
            std::cout << "    --> Returned content length: " << g_dynamicMockResponse.length() << std::endl;
            return TRUE;
        }
        
        // Return a generic response header
        return TRUE;
    }
    return Orig_WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
}

WINHTTP_STATUS_CALLBACK WINAPI Hooked_WinHttpSetStatusCallback(
    HINTERNET hInternet,
    WINHTTP_STATUS_CALLBACK lpfnCallback,
    DWORD dwNotificationFlags,
    DWORD_PTR dwReserved
) {
    if (IsMockHandle(hInternet)) {
        std::cout << "[+] Hook: Intercepted WinHttpSetStatusCallback setup!" << std::endl;
        SetHandleCallback(hInternet, lpfnCallback, 0);
        return NULL; // Return NULL (or previous callback if any, but since we mock, NULL is fine)
    }
    return Orig_WinHttpSetStatusCallback(hInternet, lpfnCallback, dwNotificationFlags, dwReserved);
}

#pragma optimize("", on)

// Hook Engine Struct
struct Hook {
    const char* apiName;
    void* targetFunc;
    void* detourFunc;
    int prologueSize;
    unsigned char originalBytes[16];
    void* trampoline;
};

void* CreateTrampoline(void* targetFunc, int prologueSize, unsigned char* originalBytes) {
    void* tramp = VirtualAlloc(NULL, prologueSize + 12, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(tramp, originalBytes, prologueSize);
    
    unsigned char* jmpBytes = (unsigned char*)tramp + prologueSize;
    jmpBytes[0] = 0x48; // mov rax, targetFunc + prologueSize
    jmpBytes[1] = 0xB8;
    void* jmpTarget = (void*)((BYTE*)targetFunc + prologueSize);
    memcpy(jmpBytes + 2, &jmpTarget, 8);
    jmpBytes[10] = 0xFF; // jmp rax
    jmpBytes[11] = 0xE0;
    
    return tramp;
}

void InstallHook(Hook* hk) {
    memcpy(hk->originalBytes, hk->targetFunc, hk->prologueSize);
    hk->trampoline = CreateTrampoline(hk->targetFunc, hk->prologueSize, hk->originalBytes);
    
    ULONG oldProtect = 0;
    BOOL protectedUsingSyscall = FALSE;
    
    if (Orig_NtProtectVirtualMemory) {
        PVOID pageAddr = (PVOID)((ULONG_PTR)hk->targetFunc & ~(4096 - 1));
        SIZE_T regionSize = 4096;
        NTSTATUS status = Orig_NtProtectVirtualMemory(GetCurrentProcess(), &pageAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        if (NT_SUCCESS(status)) {
            protectedUsingSyscall = TRUE;
        }
    }
    
    if (!protectedUsingSyscall) {
        DWORD old;
        VirtualProtectEx(GetCurrentProcess(), hk->targetFunc, hk->prologueSize, PAGE_EXECUTE_READWRITE, &old);
        oldProtect = old;
    }
    
    unsigned char patch[32];
    memset(patch, 0x90, hk->prologueSize); // NOPs
    patch[0] = 0x48; // mov rax, detour
    patch[1] = 0xB8;
    memcpy(patch + 2, &hk->detourFunc, 8);
    patch[10] = 0xFF; // jmp rax
    patch[11] = 0xE0;
    
    memcpy(hk->targetFunc, patch, hk->prologueSize);
    
    if (protectedUsingSyscall) {
        PVOID pageAddr = (PVOID)((ULONG_PTR)hk->targetFunc & ~(4096 - 1));
        SIZE_T regionSize = 4096;
        ULONG dummy;
        Orig_NtProtectVirtualMemory(GetCurrentProcess(), &pageAddr, &regionSize, oldProtect, &dummy);
    } else {
        DWORD dummy;
        VirtualProtectEx(GetCurrentProcess(), hk->targetFunc, hk->prologueSize, oldProtect, &dummy);
    }
}

PROTO_NtProtectVirtualMemory Orig_NtProtectVirtualMemory = NULL;

NTSTATUS NTAPI Hooked_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    ULONG flNew = NewProtect;
    std::cout << "[+] Hook (Nt): NtProtectVirtualMemory called for addr 0x" 
              << std::hex << (BaseAddress ? *BaseAddress : NULL) 
              << ", size 0x" << (RegionSize ? *RegionSize : 0) 
              << ", prot 0x" << NewProtect << std::endl;

    if (NewProtect == 0x60000020) {
        flNew = PAGE_EXECUTE_READWRITE;
        std::cout << "    --> Redirected flag 0x60000020 -> PAGE_EXECUTE_READWRITE" << std::endl;
    } else if (NewProtect == 0x40000040 || NewProtect == 0xC0000040 || NewProtect == 0xC0000080) {
        flNew = PAGE_READWRITE;
        std::cout << "    --> Redirected flag 0x" << std::hex << NewProtect << " -> PAGE_READWRITE" << std::endl;
    }
    
    NTSTATUS status = Orig_NtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, flNew, OldProtect);
    std::cout << "    --> Syscall returned status: 0x" << std::hex << status << std::endl;
    return status;
}

BOOL WINAPI Hooked_VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
) {
    DWORD flNew = flNewProtect;
    std::cout << "[+] Hook (VP): VirtualProtect called for addr 0x" 
              << std::hex << lpAddress << ", size 0x" << dwSize 
              << ", prot 0x" << flNewProtect << std::endl;

    if (flNewProtect == 0x60000020) {
        flNew = PAGE_EXECUTE_READWRITE;
        std::cout << "    --> Redirected flag 0x60000020 -> PAGE_EXECUTE_READWRITE" << std::endl;
    } else if (flNewProtect == 0x40000040 || flNewProtect == 0xC0000040 || flNewProtect == 0xC0000080) {
        flNew = PAGE_READWRITE;
        std::cout << "    --> Redirected flag 0x" << std::hex << flNewProtect << " -> PAGE_READWRITE" << std::endl;
    }
    
    PVOID baseAddress = lpAddress;
    SIZE_T regionSize = dwSize;
    NTSTATUS status = Orig_NtProtectVirtualMemory(GetCurrentProcess(), &baseAddress, &regionSize, flNew, lpflOldProtect);
    std::cout << "    --> Syscall returned status: 0x" << std::hex << status << std::endl;
    return NT_SUCCESS(status);
}

BOOL WINAPI Hooked_VirtualProtectEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
) {
    DWORD flNew = flNewProtect;
    std::cout << "[+] Hook (VPE): VirtualProtectEx called for addr 0x" 
              << std::hex << lpAddress << ", size 0x" << dwSize 
              << ", prot 0x" << flNewProtect << std::endl;

    if (flNewProtect == 0x60000020) {
        flNew = PAGE_EXECUTE_READWRITE;
        std::cout << "    --> Redirected flag 0x60000020 -> PAGE_EXECUTE_READWRITE" << std::endl;
    } else if (flNewProtect == 0x40000040 || flNewProtect == 0xC0000040 || flNewProtect == 0xC0000080) {
        flNew = PAGE_READWRITE;
        std::cout << "    --> Redirected flag 0x" << std::hex << flNewProtect << " -> PAGE_READWRITE" << std::endl;
    }
    
    PVOID baseAddress = lpAddress;
    SIZE_T regionSize = dwSize;
    NTSTATUS status = Orig_NtProtectVirtualMemory(hProcess, &baseAddress, &regionSize, flNew, lpflOldProtect);
    std::cout << "    --> Syscall returned status: 0x" << std::hex << status << std::endl;
    return NT_SUCCESS(status);
}

void InstallDirectHook(void* targetFunc, void* detourFunc) {
    DWORD oldProtect;
    VirtualProtectEx(GetCurrentProcess(), targetFunc, 12, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    unsigned char patch[12];
    patch[0] = 0x48; // mov rax, detour
    patch[1] = 0xB8;
    memcpy(patch + 2, &detourFunc, 8);
    patch[10] = 0xFF; // jmp rax
    patch[11] = 0xE0;
    
    memcpy(targetFunc, patch, 12);
    VirtualProtectEx(GetCurrentProcess(), targetFunc, 12, oldProtect, &oldProtect);
}

void PerformRelocations(HMODULE hModule) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    ULONG_PTR delta = (ULONG_PTR)hModule - ntHeaders->OptionalHeader.ImageBase;
    if (delta == 0) return; // No relocation needed
    
    DWORD relocRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    if (relocRVA == 0) return;
    
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)hModule + relocRVA);
    
    while (reloc->VirtualAddress != 0) {
        DWORD size = reloc->SizeOfBlock;
        DWORD count = (size - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* list = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < count; i++) {
            WORD type = list[i] >> 12;
            WORD offset = list[i] & 0x0FFF;
            
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONGLONG* patchAddr = (ULONGLONG*)((BYTE*)hModule + reloc->VirtualAddress + offset);
                *patchAddr += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* patchAddr = (DWORD*)((BYTE*)hModule + reloc->VirtualAddress + offset);
                *patchAddr += (DWORD)delta;
            }
        }
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + size);
    }
}

void ResolveImports(HMODULE hModule) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) return;
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importRVA);
    
    while (importDesc->Name != 0) {
        const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);
        HMODULE hImportDll = LoadLibraryA(dllName);
        if (!hImportDll) {
            std::cerr << "[-] Failed to load imported DLL: " << dllName << std::endl;
            importDesc++;
            continue;
        }
        
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);
        if (!thunk) thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
        
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
        
        while (thunk->u1.AddressOfData != 0) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                ULONGLONG ordinal = IMAGE_ORDINAL(thunk->u1.Ordinal);
                FARPROC funcAddr = GetProcAddress(hImportDll, (LPCSTR)ordinal);
                iat->u1.Function = (ULONGLONG)funcAddr;
            } else {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + thunk->u1.AddressOfData);
                const char* funcName = (const char*)importByName->Name;
                FARPROC funcAddr = GetProcAddress(hImportDll, funcName);
                iat->u1.Function = (ULONGLONG)funcAddr;
            }
            thunk++;
            iat++;
        }
        importDesc++;
    }
}

void CallTLSCallbacks(HMODULE hModule) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    DWORD tlsRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRVA == 0) return;
    
    PIMAGE_TLS_DIRECTORY tlsDir = (PIMAGE_TLS_DIRECTORY)((BYTE*)hModule + tlsRVA);
    
    ULONG_PTR callbacksVA = tlsDir->AddressOfCallBacks;
    if (callbacksVA == 0) return;
    
    ULONG_PTR callbacksRVA = callbacksVA - ntHeaders->OptionalHeader.ImageBase;
    PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)((BYTE*)hModule + callbacksRVA);
    
    std::cout << "[+] Executing TLS callbacks (Array RVA: 0x" << std::hex << callbacksRVA << ")..." << std::endl;
    
    while (callbacks && *callbacks) {
        ULONG_PTR callbackVA = (ULONG_PTR)*callbacks;
        ULONG_PTR callbackRVA = callbackVA - ntHeaders->OptionalHeader.ImageBase;
        
        PIMAGE_TLS_CALLBACK callbackFunc = (PIMAGE_TLS_CALLBACK)((BYTE*)hModule + callbackRVA);
        
        std::cout << "    --> Calling callback at RVA 0x" << std::hex << callbackRVA << "..." << std::endl;
        callbackFunc(hModule, DLL_PROCESS_ATTACH, NULL);
        
        callbacks++;
    }
}

HMODULE LoadPackedDLL(const char* dllPath) {
    std::cout << "[+] Loading " << dllPath << " (DONT_RESOLVE_DLL_REFERENCES)..." << std::endl;
    HMODULE hModule = LoadLibraryExA(dllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hModule) {
        std::cerr << "[-] Failed to map module: " << dllPath << "! Error: " << GetLastError() << std::endl;
        return NULL;
    }
    std::cout << "[+] Mapped module at 0x" << std::hex << hModule << std::endl;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    // Set all code/data sections to PAGE_EXECUTE_READWRITE
    std::cout << "[+] Changing section protections to PAGE_EXECUTE_READWRITE..." << std::endl;
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID sectionAddr = (BYTE*)hModule + sectionHeader[i].VirtualAddress;
        SIZE_T sectionSize = sectionHeader[i].Misc.VirtualSize;
        if (sectionSize == 0) continue;
        
        DWORD oldProtect;
        BOOL res = VirtualProtect(sectionAddr, sectionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        if (!res) {
            std::cerr << "[-] Failed to set section " << sectionHeader[i].Name << " protection! Error: " << GetLastError() << std::endl;
        }
    }
    
    // Perform relocations manually
    std::cout << "[+] Performing relocations..." << std::endl;
    PerformRelocations(hModule);

    // Resolve imports manually
    std::cout << "[+] Resolving imports..." << std::endl;
    ResolveImports(hModule);
    
    // Call TLS callbacks if present
    CallTLSCallbacks(hModule);
    
    // Call DllMain manually
    std::cout << "[+] Calling DllMain..." << std::endl;
    BOOL (WINAPI* DllMain)(HINSTANCE, DWORD, LPVOID) = 
        (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))((BYTE*)hModule + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        
    if (ntHeaders->OptionalHeader.AddressOfEntryPoint != 0) {
        BOOL res = DllMain((HINSTANCE)hModule, DLL_PROCESS_ATTACH, NULL);
        if (!res) {
            std::cerr << "[-] DllMain returned failure!" << std::endl;
            return NULL;
        }
        std::cout << "[+] DllMain called successfully!" << std::endl;
    } else {
        std::cout << "[*] No DllMain entry point found." << std::endl;
    }
    
    return hModule;
}

int main() {
    std::cout << "==========================================================" << std::endl;
    std::cout << "   BR MODS Key Validation Bypass Loader 2026 (Clean)" << std::endl;
    std::cout << "==========================================================" << std::endl;
    std::cout << "[+] Initializing Critical Section..." << std::endl;
    InitializeCriticalSection(&g_cs);
    
    // Load config from config.json
    LoadConfiguration();
    
    // Clear registry or apply key from config
    ClearPersistedKey();
    
    HMODULE hWinHttp = GetModuleHandleA("winhttp.dll");
    if (!hWinHttp) hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp) {
        std::cerr << "[-] Failed to load winhttp.dll" << std::endl;
        return 1;
    }
    
    // Hook APIs
    Hook hkConnect = { "WinHttpConnect", GetProcAddress(hWinHttp, "WinHttpConnect"), (void*)Hooked_WinHttpConnect, 13 };
    Hook hkOpen = { "WinHttpOpenRequest", GetProcAddress(hWinHttp, "WinHttpOpenRequest"), (void*)Hooked_WinHttpOpenRequest, 13 };
    Hook hkSend = { "WinHttpSendRequest", GetProcAddress(hWinHttp, "WinHttpSendRequest"), (void*)Hooked_WinHttpSendRequest, 13 };
    Hook hkRecv = { "WinHttpReceiveResponse", GetProcAddress(hWinHttp, "WinHttpReceiveResponse"), (void*)Hooked_WinHttpReceiveResponse, 15 };
    Hook hkQuery = { "WinHttpQueryDataAvailable", GetProcAddress(hWinHttp, "WinHttpQueryDataAvailable"), (void*)Hooked_WinHttpQueryDataAvailable, 16 };
    Hook hkRead = { "WinHttpReadData", GetProcAddress(hWinHttp, "WinHttpReadData"), (void*)Hooked_WinHttpReadData, 15 };
    Hook hkHeaders = { "WinHttpQueryHeaders", GetProcAddress(hWinHttp, "WinHttpQueryHeaders"), (void*)Hooked_WinHttpQueryHeaders, 12 };
    Hook hkCallback = { "WinHttpSetStatusCallback", GetProcAddress(hWinHttp, "WinHttpSetStatusCallback"), (void*)Hooked_WinHttpSetStatusCallback, 13 };
    
    std::cout << "[+] Installing WinHttp redirection hooks..." << std::endl;
    InstallHook(&hkConnect);
    Orig_WinHttpConnect = (PROTO_WinHttpConnect)hkConnect.trampoline;
    
    InstallHook(&hkOpen);
    Orig_WinHttpOpenRequest = (PROTO_WinHttpOpenRequest)hkOpen.trampoline;
    
    InstallHook(&hkSend);
    Orig_WinHttpSendRequest = (PROTO_WinHttpSendRequest)hkSend.trampoline;
    
    InstallHook(&hkRecv);
    Orig_WinHttpReceiveResponse = (PROTO_WinHttpReceiveResponse)hkRecv.trampoline;
    
    InstallHook(&hkQuery);
    Orig_WinHttpQueryDataAvailable = (PROTO_WinHttpQueryDataAvailable)hkQuery.trampoline;
    
    InstallHook(&hkRead);
    Orig_WinHttpReadData = (PROTO_WinHttpReadData)hkRead.trampoline;
    
    InstallHook(&hkHeaders);
    Orig_WinHttpQueryHeaders = (PROTO_WinHttpQueryHeaders)hkHeaders.trampoline;
    
    InstallHook(&hkCallback);
    Orig_WinHttpSetStatusCallback = (PROTO_WinHttpSetStatusCallback)hkCallback.trampoline;
    std::cout << "[+] WinHttp hooks installed successfully!" << std::endl;
    
    // Install NtProtectVirtualMemory hook dynamically
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        void* pNtProt = (void*)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
        if (pNtProt) {
            // Read the syscall number dynamically from the function body
            unsigned char* pNtProtBytes = (unsigned char*)pNtProt;
            DWORD syscallNum = *(DWORD*)(pNtProtBytes + 4);
            
            // Build the dynamic syscall stub
            unsigned char syscallStub[] = {
                0x4C, 0x8B, 0xD1,             // mov r10, rcx
                0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax, syscallNum
                0x0F, 0x05,                   // syscall
                0xC3                          // ret
            };
            *(DWORD*)(syscallStub + 4) = syscallNum;
            
            // Allocate memory for the stub
            void* stubMem = VirtualAlloc(NULL, sizeof(syscallStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (stubMem) {
                memcpy(stubMem, syscallStub, sizeof(syscallStub));
                Orig_NtProtectVirtualMemory = (PROTO_NtProtectVirtualMemory)stubMem;
                
                // std::cout << "[+] Installing NtProtectVirtualMemory direct hook..." << std::endl;
                // InstallDirectHook(pNtProt, (void*)Hooked_NtProtectVirtualMemory);
                // std::cout << "[+] NtProtectVirtualMemory hook installed successfully (Syscall: 0x" << std::hex << syscallNum << ")!" << std::endl;
            }
        }
    }
    
    // Hook VirtualProtect and VirtualProtectEx in kernel32.dll and KernelBase.dll commented out
    /*
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (hK32) {
        void* pVP = (void*)GetProcAddress(hK32, "VirtualProtect");
        if (pVP) {
            std::cout << "[+] Installing kernel32.dll VirtualProtect direct hook..." << std::endl;
            InstallDirectHook(pVP, (void*)Hooked_VirtualProtect);
        }
        void* pVPE = (void*)GetProcAddress(hK32, "VirtualProtectEx");
        if (pVPE) {
            std::cout << "[+] Installing kernel32.dll VirtualProtectEx direct hook..." << std::endl;
            InstallDirectHook(pVPE, (void*)Hooked_VirtualProtectEx);
        }
    }
    
    HMODULE hKB = GetModuleHandleA("KernelBase.dll");
    if (!hKB) hKB = LoadLibraryA("KernelBase.dll");
    if (hKB) {
        void* pVP = (void*)GetProcAddress(hKB, "VirtualProtect");
        if (pVP) {
            std::cout << "[+] Installing KernelBase.dll VirtualProtect direct hook..." << std::endl;
            InstallDirectHook(pVP, (void*)Hooked_VirtualProtect);
        }
        void* pVPE = (void*)GetProcAddress(hKB, "VirtualProtectEx");
        if (pVPE) {
            std::cout << "[+] Installing KernelBase.dll VirtualProtectEx direct hook..." << std::endl;
            InstallDirectHook(pVPE, (void*)Hooked_VirtualProtectEx);
        }
    }
    */
    
    // Load khoahihi.dll (original packed with writable sections)
    std::cout << "[+] Loading khoahihi.dll (original packed)..." << std::endl;
    HMODULE hKhoa = LoadLibraryA("khoahihi.dll");
    if (!hKhoa) {
        std::cerr << "[-] Failed to load khoahihi.dll! Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Successfully loaded khoahihi.dll at 0x" << std::hex << hKhoa << std::endl;

    // Dynamic memory patch using NtProtectVirtualMemory syscall to bypass key check disabled
    // (Integrity patching khoahihi.dll triggers anti-tamper "TAMPER_DETECTED" and causes verification fail)
    /*
    if (Orig_NtProtectVirtualMemory) {
        std::cout << "[+] Applying in-memory bypass patches..." << std::endl;
        
        struct MemoryPatch {
            DWORD rva;
            unsigned char original[2];
            unsigned char patch[2];
        } patches[] = {
            { 0x2DF62, { 0x75, 0x5B }, { 0xEB, 0x5B } },
            { 0x2E07E, { 0x75, 0x1D }, { 0xEB, 0x1D } }
        };
        
        for (int i = 0; i < 2; i++) {
            void* patchAddr = (void*)((BYTE*)hKhoa + patches[i].rva);
            
            // Query page alignment
            PVOID pageAddr = (PVOID)((ULONG_PTR)patchAddr & ~(4096 - 1));
            SIZE_T regionSize = 4096;
            ULONG oldProtect = 0;
            
            // Set PAGE_EXECUTE_READWRITE
            NTSTATUS status = Orig_NtProtectVirtualMemory(GetCurrentProcess(), &pageAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            if (NT_SUCCESS(status)) {
                // Verify original bytes
                unsigned char currentBytes[2];
                memcpy(currentBytes, patchAddr, 2);
                if (currentBytes[0] == patches[i].original[0] && currentBytes[1] == patches[i].original[1]) {
                    memcpy(patchAddr, patches[i].patch, 2);
                    std::cout << "[+] Patch applied successfully at RVA 0x" << std::hex << patches[i].rva << std::endl;
                } else {
                    std::cout << "[!] Warning: Original bytes mismatch at RVA 0x" << std::hex << patches[i].rva 
                              << ". Found: " << std::hex << (int)currentBytes[0] << " " << (int)currentBytes[1] << std::endl;
                }
                
                // Restore page protection
                Orig_NtProtectVirtualMemory(GetCurrentProcess(), &pageAddr, &regionSize, oldProtect, &oldProtect);
            } else {
                std::cerr << "[-] Failed to change protection for RVA 0x" << std::hex << patches[i].rva 
                          << ". Status: 0x" << std::hex << status << std::endl;
            }
        }
    } else {
        std::cerr << "[-] NtProtectVirtualMemory syscall stub is null. Cannot apply memory patches!" << std::endl;
    }
    */
    
    // Call HDGLView3940SkipLoginStart
    void (*pStart)() = (void(*)())GetProcAddress(hKhoa, "HDGLView3940SkipLoginStart");
    if (!pStart) {
        std::cerr << "[-] Failed to find HDGLView3940SkipLoginStart export!" << std::endl;
        return 1;
    }
    
    std::cout << "[+] Calling HDGLView3940SkipLoginStart..." << std::endl;
    pStart();
    std::cout << "[+] Called HDGLView3940SkipLoginStart successfully!" << std::endl;
    
    // Load minduin.dll (original packed with writable sections)
    std::cout << "[+] Loading minduin.dll (original packed)..." << std::endl;
    HMODULE hMind = LoadLibraryA("minduin.dll");
    if (!hMind) {
        std::cerr << "[-] Failed to load minduin.dll! Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Successfully loaded minduin.dll at 0x" << std::hex << hMind << std::endl;
    
    std::cout << "\n[+] loader running. Cheat menu active." << std::endl;
    std::cout << "[*] Note: If the login screen pops up, enter any random character (e.g. '1') as key and click login." << std::endl;
    std::cout << "[*] It will activate instantly and save the key, so next time it will open directly." << std::endl;
    std::cout << "[+] Close this console window to exit the cheat." << std::endl;
    
    while (true) {
        Sleep(1000);
    }
    return 0;
}
