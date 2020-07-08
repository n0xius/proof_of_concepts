# CMakeList.txt : CMake project for pocs, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (map_pe_via_section "map_pe_via_section.c")
add_executable (ntfs_transactions "ntfs_transactions.c")

target_link_libraries(map_pe_via_section ntdll.lib)
target_link_libraries(ntfs_transactions ntdll.lib)