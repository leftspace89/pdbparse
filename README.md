pdbparse: a C++ library which will automatically download a module's PDB file, then parse it for a function address
all cached data are stored in the temp folder (C:\users\user\AppData\Local\Temp\pdbname.pdb\guid), with this data being the PDB itself and a .txt file which stores any addresses it found.
if the given pdb filename can be found elsewhere (it's in the same directory as the executable, or the pdb name is a valid full path), the .txt file is created there.

this depends on the following libraries:
diaguids.lib, for parsing the .pdb file
urlmon.lib, for downloading the .pdb file

you also need a C++17-compliant compiler.
this project was compiled with MSVC using Visual Studio version 15.5.1

this supports both x86 and x64, with the example being x64.