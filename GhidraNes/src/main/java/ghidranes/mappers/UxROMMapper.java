package ghidranes.mappers;

import java.util.Arrays;

import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import ghidranes.NesRom;
import ghidranes.util.MemoryBlockDescription;

public class UxROMMapper extends NesMapper {
    @Override
    public void updateMemoryMapForRom(NesRom rom, Program program, TaskMonitor monitor) throws LockException, MemoryConflictException, AddressOverflowException, CancelledException, DuplicateNameException {

        /* UxROM has switchable 16k PRG ROM banks mapped at 8000-BFFF.
           The upper bank (fixed at C000-FFFF) is typically the last bank, and 
           the lower bank (8000-BFFF) is switchable. */
        int bankCount = rom.prgRom.length / 0x4000;

        // Load switchable lower banks
        for (int bank = 0; bank < bankCount - 1; bank++) {
            int lowerBankPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;

            byte[] lowerBankBytes = Arrays.copyOfRange(rom.prgRom, bank*0x4000, (bank+1)*0x4000);
            MemoryBlockDescription.initialized(0x8000, 0x4000, "PRG Lower " + bank, lowerBankPermissions, lowerBankBytes, bank > 0, monitor)
                .create(program);
        }

        // Load the fixed lower bank (first 16KB)
        int upperBankPermissions = MemoryBlockDescription.READ | MemoryBlockDescription.EXECUTE;
        byte[] upperBankBytes = Arrays.copyOfRange(rom.prgRom, (bankCount - 1)*0x4000, bankCount*0x4000);
        MemoryBlockDescription.initialized(0xC000, 0x4000, "PRG Upper", upperBankPermissions, upperBankBytes, false, monitor)
            .create(program);


    }
}
