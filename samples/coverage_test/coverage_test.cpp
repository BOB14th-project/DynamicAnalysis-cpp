#include <iostream>
#include <string>
#include <vector>
#include <limits> // 입력 버퍼 클리어를 위해 추가
#include <openssl/evp.h>
#include <openssl/rand.h>

// 에러 처리 함수
void handleErrors() {
    std::cerr << "An error occurred in OpenSSL." << std::endl;
    abort();
}

// AES-GCM 암호화 함수 (변경 없음)
bool aes_gcm_encrypt(const std::vector<unsigned char>& plaintext,
                     const std::vector<unsigned char>& aad,
                     const std::vector<unsigned char>& key,
                     std::vector<unsigned char>& iv,
                     std::vector<unsigned char>& ciphertext,
                     std::vector<unsigned char>& tag) {
    
    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    int ciphertext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL)) handleErrors();
    
    iv.resize(12);
    if (1 != RAND_bytes(iv.data(), iv.size())) handleErrors();
    
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) handleErrors();
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad.data(), aad.size())) handleErrors();
    
    ciphertext.resize(plaintext.size());
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) handleErrors();
    ciphertext_len = len;
    
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) handleErrors();
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    
    tag.resize(16);
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) handleErrors();

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// AES-GCM 복호화 함수 (변경 없음)
bool aes_gcm_decrypt(const std::vector<unsigned char>& ciphertext,
                     const std::vector<unsigned char>& aad,
                     const std::vector<unsigned char>& tag,
                     const std::vector<unsigned char>& key,
                     const std::vector<unsigned char>& iv,
                     std::vector<unsigned char>& decryptedtext) {

    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    int decryptedtext_len = 0;
    int ret = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) handleErrors();
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) handleErrors();
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad.data(), aad.size())) handleErrors();
    
    decryptedtext.resize(ciphertext.size());
    if (!EVP_DecryptUpdate(ctx, decryptedtext.data(), &len, ciphertext.data(), ciphertext.size())) handleErrors();
    decryptedtext_len = len;
    
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data())) handleErrors();
    
    ret = EVP_DecryptFinal_ex(ctx, decryptedtext.data() + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        decryptedtext_len += len;
        decryptedtext.resize(decryptedtext_len);
        return true;
    } else {
        decryptedtext.clear();
        return false;
    }
}

// --- 분기 구조가 추가된 main 함수 ---
int main() {
    while (true) {
        std::cout << "\n===== MENU =====" << std::endl;
        std::cout << "1. Run Encryption/Decryption Example" << std::endl;
        std::cout << "2. Exit" << std::endl;
        std::cout << ">> ";

        int choice;
        std::cin >> choice;

        // 사용자가 숫자가 아닌 값을 입력했을 경우에 대한 예외 처리
        if (std::cin.fail()) {
            std::cin.clear(); // 에러 플래그 초기화
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // 입력 버퍼 비우기
            choice = 0; // 잘못된 선택으로 처리
        }

        if (choice == 1) {
            // 256비트 (32바이트) 암호화 키
            std::vector<unsigned char> key(32);
            if(!RAND_bytes(key.data(), key.size())) handleErrors();

            // 평문
            std::vector<unsigned char> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'S', 'e', 'c', 'u', 'r', 'e', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
            
            // 추가 인증 데이터 (메타데이터 등)
            std::vector<unsigned char> aad = {'S', 'o', 'm', 'e', ' ', 'A', 'A', 'D'};

            // 암호화 결과물을 저장할 변수들
            std::vector<unsigned char> iv;
            std::vector<unsigned char> ciphertext;
            std::vector<unsigned char> tag;

            // 암호화 수행
            if (aes_gcm_encrypt(plaintext, aad, key, iv, ciphertext, tag)) {
                std::cout << "\n[INFO] Encryption successful." << std::endl;
            } else {
                std::cerr << "\n[ERROR] Encryption failed." << std::endl;
                continue; // 메뉴로 돌아가기
            }

            // 복호화 결과물을 저장할 변수
            std::vector<unsigned char> decryptedtext;

            // 복호화 수행
            if (aes_gcm_decrypt(ciphertext, aad, tag, key, iv, decryptedtext)) {
                std::cout << "[INFO] Decryption successful." << std::endl;
                std::cout << "       -> Decrypted Text: " << std::string(decryptedtext.begin(), decryptedtext.end()) << std::endl;
            } else {
                std::cerr << "[ERROR] Decryption failed. (Authentication Tag Mismatch)" << std::endl;
            }

        } else if (choice == 2) {
            std::cout << "\nExiting program." << std::endl;
            break; // while 루프 탈출
        } else {
            std::cout << "\n[WARN] Invalid choice. Please enter 1 or 2." << std::endl;
        }
    }

    return 0;
}