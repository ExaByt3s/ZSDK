#include "common/rl_kernel.h"

#include "common/cui.h"
#include "common/console.h"
#include "common/str.h"

void Cui::init(void)
{

}

void Cui::uninit(void)
{

}

Cui::COMMAND *Cui::_getCommand(const LPWSTR *args, int argsCount, const COMMAND *commands, BYTE commandsCount)
{
  if(argsCount > 1)for(BYTE i = 0; i < commandsCount; i++)if(Str::_CompareW(commands[i].name, args[1], -1, -1) == 0)return (Cui::COMMAND *)&commands[i];
  return NULL;
}

DWORD Cui::_checkSwitches(const LPWSTR *args, int argsCount, const SWITCH *switches, BYTE switchesCount)
{
  //����� �����.
  for(int i = 2; i < argsCount; i++)
  {
    //����� ������ ���������� � -.
    if(args[i][0] != '-')return MAKELONG(1, i);

    //�������� ��������� �����.
    LPWSTR name       = args[i] + 1;
    LPWSTR dataOfName = CWA(shlwapi, StrChrW)(name, ':');
    BYTE j            = 0;

    for(; j < switchesCount; j++)
    {
      LPWSTR realName       = switches[j].name;
      LPWSTR dataOfRealName = Str::_findCharW(realName, ':');
      if(dataOfName != NULL && dataOfRealName != NULL)
      {
        //����� � ����������.
        int size = (int)(dataOfRealName - realName);
        if(size == (int)(dataOfName - name) && Str::_CompareW(name, realName, size, size) == 0)
        {
          if(*(dataOfName + 1) == 0)return MAKELONG(1, i);
          break;
        }
      }
      //����� ��� ���������.
      else
      {
        if(dataOfName == NULL && dataOfRealName == NULL && Str::_CompareW(name, realName, -1, -1) == 0)break;
      }
    }

    //����������� �����.
    if(j == switchesCount)return MAKELONG(2, i);
  }

  return 0;
}

LPWSTR Cui::_getSwitchValue(const LPWSTR *switches, DWORD switchesCount, const LPWSTR requeredSwitch)
{
  int switchLen = Str::_LengthW(requeredSwitch);
  
  //����� �����.
  for(DWORD i = 0; i < switchesCount; i++)if(switches[i] != NULL && switches[i][0] == '-')
  {
    //�������� ��������� �����.
    LPWSTR name       = switches[i] + 1;
    LPWSTR dataOfName = Str::_findCharW(name, ':');
    int currentLen    = dataOfName == NULL ? Str::_LengthW(name) : dataOfName - name;
    
    if(currentLen == switchLen && Str::_CompareW(name, requeredSwitch, switchLen, switchLen) == 0)
    {
      if(dataOfName == NULL)return (LPWSTR)1;
      
      dataOfName++;
      CWA(shlwapi, PathUnquoteSpacesW)(dataOfName);
      return dataOfName;
    }
  }

  return NULL;
}

void Cui::_showHelp(const COMMAND *commands, BYTE commandsCount, const LPWSTR mainTitle, const LPWSTR fileName)
{
  Console::writeFormatW(mainTitle, fileName != NULL ? fileName : L"");

  //�������
  for(BYTE i = 0; i < commandsCount; i++)
  {
    COMMAND *currentCommand = (COMMAND *)&commands[i];
    if(i > 0)Console::writeStringW(L"\n", 1);
    Console::writeFormatW(L"%-20s %s\n", currentCommand->name, currentCommand->description);

    //�����
    for(BYTE j = 0; j < currentCommand->switchesCount; j++)
    {
      SWITCH *currentSwitch = &currentCommand->switches[j];
      Console::writeFormatW(L"  -%-17s %s\n", currentSwitch->name, currentSwitch->description);
    }
  }
}
