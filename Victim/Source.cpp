#include <Windows.h>
#include <iostream>

int __stdcall StdCallSum(int a, int b)
{
	std::cout << "StdCallSum is called" << std::endl;
	return a + b;
}

int __cdecl CdeclSum(int a, int b)
{
	std::cout << "CdeclSum is called" << std::endl;
	return a + b;
}

int main()
{
	std::cout << "Function address of StdCallSum: 0x" << std::hex << StdCallSum << std::endl;
	std::cout << "Function address of CdeclSum: 0x" << std::hex << CdeclSum << std::endl;

	while (true)
	{
		std::cout << ".";
		Sleep(500);
	}

	return 0;
}
