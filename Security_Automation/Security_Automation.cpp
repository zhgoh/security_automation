/*
Author: Goh Zi He

Description: 
Write a script to find all annoying process that is spawned from a sleep process
which has md5 as their process name. Also kill the process and point the remote ip 
of the annoying process to localhost in the host file.

Note:
To build the project, make sure to run VS 2017 with admin rights, currently I have
set the project to require elevation when started so that I can write to the hosts
file.
*/
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <regex>

#include <Windows.h>
#include <tchar.h>
#include <psapi.h>
#include <iphlpapi.h>

#pragma comment(lib,"iphlpapi")
#pragma comment(lib,"wsock32")

std::vector<DWORD> GetProcessWithMD5();
std::vector<std::wstring> FindServer(const std::vector<DWORD> &annoyingPIDs, std::vector<DWORD> &toBeKilled);
void KillAllAnnoying(const std::vector<DWORD> &annoyingPIDs);
void AddToHostFile(const std::vector<std::wstring> &blacklist);

// Note: Sleeper might spawn 3 or more annoying child process with md5 names
int main()
{
  // Considerations:
  // Will this process get killed by the sleeper?
  // Do I need to restart this process if it is killed then
  const auto waitDuration = 5 * 60 * 1000;
  std::vector<DWORD> md5Pids;
  std::vector<DWORD> toBeKilled;
  std::vector<std::wstring> blacklist;

  std::cout << "Started to monitor for annoying process\n\n";

  while (true)
  {
    // Find all the program id which have md5 name as process name
    md5Pids = GetProcessWithMD5();

    // Find the C&C server the process is connected to
    blacklist = FindServer(md5Pids, toBeKilled);

    // Kill the annoying process
    KillAllAnnoying(toBeKilled);

    // Write the server to host file
    AddToHostFile(blacklist);

    std::cout << "This process is going to sleep for " << waitDuration << std::endl << std::endl;
    Sleep(waitDuration);

    md5Pids.clear();
    toBeKilled.clear();
    blacklist.clear();
  }

  return 0;
}

std::wstring GetProcessName(DWORD pid)
{
  // Query process name using pid
  TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
      PROCESS_VM_READ, FALSE, pid);

  if (!hProcess)
    return szProcessName;

  HMODULE hMod;
  DWORD cbNeeded;

  if (!EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
  {
    CloseHandle(hProcess);
    return szProcessName;
  }

  // Getting name of process for pid
  GetModuleBaseName(hProcess, hMod, szProcessName,
      sizeof(szProcessName) / sizeof(TCHAR));
  CloseHandle(hProcess);

  return szProcessName;
}

bool IsProcessNameMD5(DWORD pid)
{
  // Using a regex to match process name, our regex contains on 32 digits/letters
  auto processName = GetProcessName(pid);
  return std::regex_match(processName, std::wregex(L"([\\w\\d]{32}).exe"));
}

std::vector<DWORD> GetProcessWithMD5()
{
  std::cout << "Scanning for process with md5 names\n";

  // Get all the process using Win API
  DWORD aProcesses[1024], cbNeeded, cProcesses;
  if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
  {
    std::cout << "Error getting processes!\n";
    return {};
  }

  std::vector<DWORD> md5Pids;
  // Check whether if process name matches md5
  cProcesses = cbNeeded / sizeof(DWORD);
  for (unsigned int i = 0; i < cProcesses; ++i)
  {
    if (aProcesses[i])
      if (IsProcessNameMD5(aProcesses[i]))
        md5Pids.push_back(aProcesses[i]);
  }
  return md5Pids;
}

void KillAllAnnoying(const std::vector<DWORD> &annoyingPIDs)
{
  std::cout << "Killing all annoying process\n";

  for (auto pid : annoyingPIDs)
  {
    HANDLE hdl = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE, TRUE, pid);
    TerminateProcess(hdl, 0);
    std::cout << "Killed pid: " << pid << std::endl;
  }
}

std::vector<std::wstring> FindServer(const std::vector<DWORD> &md5Pids, std::vector<DWORD> &toBeKilled)
{
  std::vector<std::wstring> blacklist;
  std::vector<unsigned char> buffer;
  DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
  DWORD dwRetValue = 0;

  // GetExtendedTcpTable call will fail when the estimates is wrong,
  // everytime we GetExtendedTcpTable, we will get a bigger size which
  // we will call GetExtendedTcpTable again.
  do 
  {
    buffer.resize(dwSize, 0);
    dwRetValue = GetExtendedTcpTable(buffer.data(), &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  } while( dwRetValue == ERROR_INSUFFICIENT_BUFFER);

  if (dwRetValue == ERROR_SUCCESS)
  {
    PMIB_TCPTABLE_OWNER_PID ptTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    for (auto pid : md5Pids)
    {
      for (DWORD i = 0; i < ptTable->dwNumEntries; ++i)
      {
        // Get the remote address that the annoying process is trying to access
        // Also ensure that it is connecting to port 4444
        auto port = htons(static_cast<unsigned short>(ptTable->table[i].dwRemotePort));
        if (port != 4444)
          continue;

        const DWORD currentPid = ptTable->table[i].dwOwningPid;
        if (pid != currentPid)
          continue;

        // Kill only process that have port 4444
        toBeKilled.push_back(currentPid);

        std::wstringstream ss;
        // Getting the ip, we have to mask the bits
        ss << (ptTable->table[i].dwRemoteAddr & 0xFF)
          << "."
          << ((ptTable->table[i].dwRemoteAddr >> 8) & 0xFF)
          << "."
          << ((ptTable->table[i].dwRemoteAddr >> 16) & 0xFF)
          << "."
          << ((ptTable->table[i].dwRemoteAddr >> 24) & 0xFF);
        blacklist.push_back(ss.str());
      }
    }
  }
  return blacklist;
}

void AddToHostFile(const std::vector<std::wstring> &blacklist)
{
  std::cout << "Writing to host file\n";
  if (blacklist.empty())
    return;

  std::wofstream ofs(L"C:\\Windows\\System32\\drivers\\etc\\hosts", std::fstream::app);
  if (ofs.bad())
  {
    std::cout << "Error reading hosts file" << std::endl;
    return;
  }

  for (const auto &ip : blacklist)
    ofs << ip << '\t' << "localhost" << '\n';
  ofs.close();
}
