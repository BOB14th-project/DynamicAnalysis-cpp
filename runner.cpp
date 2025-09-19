// runner.cpp
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iterator>
#include <iomanip>   // std::quoted
#include <unistd.h>

// ---- 간단 유틸 ----
static std::string readFile(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    return std::string(std::istreambuf_iterator<char>(ifs),
                       std::istreambuf_iterator<char>());
}

static bool writeFile(const std::string& path, const std::string& data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(data.data(), static_cast<std::streamsize>(data.size()));
    return ofs.good();
}

static std::string replaceAll(std::string s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.length(), to);
        pos += to.length();
    }
    return s;
}

struct Options {
    std::string target;                  // 실행할 대상 바이너리(ELF)
    std::vector<std::string> targetArgs; // -- 뒤로 넘긴 인자들
    std::string out = "events.ndjson";   // 에이전트가 쓰는 NDJSON 경로
    std::string agentPath = "agent.js";  // 에이전트 템플릿 경로(그냥 파일이어도 OK)
};

static void usage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " --target /path/to/bin [--out file.ndjson] [--agent agent.js] [-- args...]\n";
}

int main(int argc, char** argv) {
    Options opt;

    // ---- 인자 파싱 ----
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--target" && i + 1 < argc) { opt.target = argv[++i]; }
        else if (a == "--out" && i + 1 < argc) { opt.out = argv[++i]; }
        else if (a == "--agent" && i + 1 < argc) { opt.agentPath = argv[++i]; }
        else if (a == "--") {
            for (int j = i + 1; j < argc; ++j) opt.targetArgs.push_back(argv[j]);
            break;
        } else {
            // 알 수 없는 옵션은 무시
        }
    }
    if (opt.target.empty()) { usage(argv[0]); return 2; }

    // ---- 에이전트 템플릿 읽고 출력 경로 치환 ----
    std::string agent = readFile(opt.agentPath);
    if (agent.empty()) {
        std::cerr << "Failed to read agent template: " << opt.agentPath << "\n";
        return 3;
    }

    // Windows 경로 백슬래시 이스케이프(WSL에서 파일경로 문자열 안전)
    std::string escapedOut = opt.out;
    for (size_t pos = 0; (pos = escapedOut.find("\\", pos)) != std::string::npos; pos += 2)
        escapedOut.replace(pos, 1, "\\\\");
    agent = replaceAll(agent, "%OUTPUT_FILE_PATH%", escapedOut);
    // (템플릿에 %OUTPUT_FILE_PATH%가 없어도 무해)

    // ---- 임시 에이전트 파일 저장 ----
    std::filesystem::path tmpAgent =
        std::filesystem::temp_directory_path() / ("agent_" + std::to_string(::getpid()) + ".js");
    if (!writeFile(tmpAgent.string(), agent)) {
        std::cerr << "Failed to write temp agent: " << tmpAgent << "\n";
        return 4;
    }

    // ---- frida -f 로 직접 스폰하고, --no-pause 로 자동 재개 ----
    std::ostringstream cmd;
    // "/bin/sh -lc " 와 "printf...|" 부분을 제거합니다.
    cmd << "frida -q -f " << std::quoted(opt.target);

    for (const auto& a : opt.targetArgs) {
        cmd << " --argv=" << std::quoted(a);
    }

    cmd << " --l " << std::quoted(tmpAgent.string());
    // 맨 뒤의 큰따옴표도 제거합니다.

    std::cerr << "[i] Running: " << cmd.str() << "\n";
    int rc = std::system(cmd.str().c_str());
    std::cerr << "[i] Frida exited with code " << rc << ". NDJSON => " << opt.out << "\n";

    return (rc == 0 ? 0 : 1);
}
