pdbparse: A C++ library which will automatically download a module's PDB file, then parse it for a function address.

All cached data are stored in the temp folder (C:\users\user\AppData\Local\Temp\pdbname.pdb\guid), with this data being the PDB itself and a .txt file which stores any addresses it found.

If the given pdb filename can be found elsewhere (it's in the same directory as the executable, or the pdb name is a valid full path), the .txt file is created there.

This depends on the following libraries:

diaguids.lib, for parsing the .pdb file

urlmon.lib, for downloading the .pdb file

You also need a C++17-compliant compiler.


This supports both x86 and x64, including the example.