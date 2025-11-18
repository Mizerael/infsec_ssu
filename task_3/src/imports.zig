const std = @import("std");
const pe = @import("pe.zig");

const network_functions = std.StaticStringMap(void).initComptime(.{
    .{"DeleteIPAddress"},
    .{"FreeMibTable"},
    .{"GetAdaptersAddresses"},
    .{"GetAnycastIpAddressEntry"},
    .{"GetAnycastIpAddressTable"},
    .{"GetBestRoute2"},
    .{"GetHostNameW"},
    .{"GetIpAddrTable"},
    .{"GetIpStatisticsEx"},
    .{"GetUnicastIpAddressTable"},
    .{"IcmpCloseHandle"},
    .{"IcmpCreateFile"},
    .{"IcmpSendEcho"},
    .{"MultinetGetConnectionPerformance"},
    .{"MultinetGetConnectionPerformanceW"},
    .{"NetAlertRaise"},
    .{"NetAlertRaiseEx"},
    .{"NetApiBufferAllocate"},
    .{"NetApiBufferFree"},
    .{"NetApiBufferReallocate"},
    .{"NetApiBufferSize"},
    .{"NetFreeAadJoinInformation"},
    .{"NetGetAadJoinInformation"},
    .{"NetAddAlternateComputerName"},
    .{"NetCreateProvisioningPackage"},
    .{"NetEnumerateComputerNames"},
    .{"NetGetJoinableOUs"},
    .{"NetGetJoinInformation"},
    .{"NetJoinDomain"},
    .{"NetProvisionComputerAccount"},
    .{"NetRemoveAlternateComputerName"},
    .{"NetRenameMachineInDomain"},
    .{"NetRequestOfflineDomainJoin"},
    .{"NetRequestProvisioningPackageInstall"},
    .{"NetSetPrimaryComputerName"},
    .{"NetUnjoinDomain"},
    .{"NetValidateName"},
    .{"NetGetAnyDCName"},
    .{"NetGetDCName"},
    .{"NetGetDisplayInformationIndex"},
    .{"NetQueryDisplayInformation"},
    .{"NetGroupAdd"},
    .{"NetGroupAddUser"},
    .{"NetGroupDel"},
    .{"NetGroupDelUser"},
    .{"NetGroupEnum"},
    .{"NetGroupGetInfo"},
    .{"NetGroupGetUsers"},
    .{"NetGroupSetInfo"},
    .{"NetGroupSetUsers"},
    .{"NetLocalGroupAdd"},
    .{"NetLocalGroupAddMembers"},
    .{"NetLocalGroupDel"},
    .{"NetLocalGroupDelMembers"},
    .{"NetLocalGroupEnum"},
    .{"NetLocalGroupGetInfo"},
    .{"NetLocalGroupGetMembers"},
    .{"NetLocalGroupSetInfo"},
    .{"NetLocalGroupSetMembers"},
    .{"NetMessageBufferSend"},
    .{"NetMessageNameAdd"},
    .{"NetMessageNameDel"},
    .{"NetMessageNameEnum"},
    .{"NetMessageNameGetInfo"},
    .{"NetFileClose"},
    .{"NetFileEnum"},
    .{"NetFileGetInfo"},
    .{"NetRemoteComputerSupports"},
    .{"NetRemoteTOD"},
    .{"NetScheduleJobAdd"},
    .{"NetScheduleJobDel"},
    .{"NetScheduleJobEnum"},
    .{"NetScheduleJobGetInfo"},
    .{"GetNetScheduleAccountInformation"},
    .{"SetNetScheduleAccountInformation"},
    .{"NetServerDiskEnum"},
    .{"NetServerEnum"},
    .{"NetServerGetInfo"},
    .{"NetServerSetInfo"},
    .{"NetServerComputerNameAdd"},
    .{"NetServerComputerNameDel"},
    .{"NetServerTransportAdd"},
    .{"NetServerTransportAddEx"},
    .{"NetServerTransportDel"},
    .{"NetServerTransportEnum"},
    .{"NetWkstaTransportEnum"},
    .{"NetUseAdd"},
    .{"NetUseDel"},
    .{"NetUseEnum"},
    .{"NetUseGetInfo"},
    .{"NetUserAdd"},
    .{"NetUserChangePassword"},
    .{"NetUserDel"},
    .{"NetUserEnum"},
    .{"NetUserGetGroups"},
    .{"NetUserGetInfo"},
    .{"NetUserGetLocalGroups"},
    .{"NetUserSetGroups"},
    .{"NetUserSetInfo"},
    .{"NetUserModalsGet"},
    .{"NetUserModalsSet"},
    .{"NetValidatePasswordPolicyFree"},
    .{"NetValidatePasswordPolicy"},
    .{"NetWkstaGetInfo"},
    .{"NetWkstaSetInfo"},
    .{"NetWkstaUserEnum"},
    .{"NetWkstaUserGetInfo"},
    .{"NetWkstaUserSetInfo"},
    .{"NetAccessAdd"},
    .{"NetAccessCheck"},
    .{"NetAccessDel"},
    .{"NetAccessEnum"},
    .{"NetAccessGetInfo"},
    .{"NetAccessGetUserPerms"},
    .{"NetAccessSetInfo"},
    .{"NetAuditClear"},
    .{"NetAuditRead"},
    .{"NetAuditWrite"},
    .{"NetConfigGet"},
    .{"NetConfigGetAll"},
    .{"NetConfigSet"},
    .{"NetErrorLogClear"},
    .{"NetErrorLogRead"},
    .{"NetErrorLogWrite"},
    .{"NetLocalGroupAddMember"},
    .{"NetLocalGroupDelMember"},
    .{"NetServiceControl"},
    .{"NetServiceEnum"},
    .{"NetServiceGetInfo"},
    .{"NetServiceInstall"},
    .{"NetWkstaTransportAdd"},
    .{"NetWkstaTransportDel"},
    .{"NetpwNameValidate"},
    .{"NetapipBufferAllocate"},
    .{"NetpwPathType"},
    .{"WNetAddConnection2"},
    .{"WNetAddConnection2W"},
    .{"WNetAddConnection3"},
    .{"WNetAddConnection3W"},
    .{"WNetCancelConnection"},
    .{"WNetCancelConnectionW"},
    .{"WNetCancelConnection2"},
    .{"WNetCancelConnection2W"},
    .{"WNetCloseEnum"},
    .{"WNetCloseEnumW"},
    .{"WNetConnectionDialog"},
    .{"WNetConnectionDialogW"},
    .{"WNetConnectionDialog1"},
    .{"WNetConnectionDialog1W"},
    .{"WNetDisconnectDialog"},
    .{"WNetDisconnectDialogW"},
    .{"WNetDisconnectDialog1"},
    .{"WNetDisconnectDialog1W"},
    .{"WNetEnumResource"},
    .{"WNetEnumResourceW"},
    .{"WNetGetConnection"},
    .{"WNetGetConnectionW"},
    .{"WNetGetLastError"},
    .{"WNetGetLastErrorW"},
    .{"WNetGetNetworkInformation"},
    .{"WNetGetNetworkInformationW"},
    .{"WNetGetProviderName"},
    .{"WNetGetProviderNameW"},
    .{"WNetGetResourceInformation"},
    .{"WNetGetResourceInformationW"},
    .{"WNetGetResourceParent"},
    .{"WNetGetResourceParentW"},
    .{"WNetGetUniversalName"},
    .{"WNetGetUniversalNameW"},
    .{"WNetGetUser"},
    .{"WNetGetUserW"},
    .{"WNetOpenEnum"},
    .{"WNetOpenEnumW"},
    .{"WNetRestoreConnectionW"},
    .{"WNetUseConnection"},
    .{"WNetUseConnectionW"},
});

pub const ImportAnalyzer = struct {
    pub fn init() ImportAnalyzer {
        return ImportAnalyzer{};
    }

    pub fn findNetworkFunctions(
        self: ImportAnalyzer,
        pe_file: *pe.PeFile,
        context: anytype,
        callback: fn (ctx: @TypeOf(context), dll_name: []const u8, function_name: []const u8) void,
    ) !void {
        _ = self;

        const import_dir = try pe_file.getImportDirectory() orelse return;
        if (import_dir.virtual_address == 0 or import_dir.size == 0) return;

        const import_offset = pe_file.rvaToFileOffset(import_dir.virtual_address) orelse return;
        if (import_offset + import_dir.size > pe_file.data.len) return;

        var descriptor_offset: usize = import_offset;

        while (true) {
            const desc = pe_file.readImportDescriptor(descriptor_offset) orelse break;

            if (desc.original_first_thunk == 0 and desc.name == 0 and desc.first_thunk == 0) break;

            const name_offset = pe_file.rvaToFileOffset(desc.name);
            if (name_offset) |no| {
                const dll_name = pe_file.readNullTerminatedString(no) orelse {
                    descriptor_offset += 20;
                    continue;
                };

                const thunk_rva = if (desc.original_first_thunk != 0) desc.original_first_thunk else desc.first_thunk;
                if (thunk_rva == 0) {
                    descriptor_offset += 20;
                    continue;
                }

                const thunk_offset = pe_file.rvaToFileOffset(thunk_rva);

                if (thunk_offset) |to| {
                    const thunk_size: usize = if (pe_file.is_64bit) 8 else 4;
                    var thunk_index: usize = 0;

                    while (true) {
                        const thunk_addr = to + thunk_index * thunk_size;

                        if (thunk_addr + thunk_size > pe_file.data.len) break;

                        const thunk_data = pe_file.readThunkData(thunk_addr) orelse break;

                        if (thunk_data == 0) break;

                        const is_ordinal = if (pe_file.is_64bit)
                            (thunk_data & (@as(u64, 1) << 63)) != 0
                        else
                            (thunk_data & (@as(u32, 1) << 31)) != 0;

                        if (!is_ordinal) {
                            const name_rva = if (pe_file.is_64bit)
                                @as(u32, @intCast(thunk_data & 0xFFFFFFFF))
                            else
                                @as(u32, @intCast(thunk_data));

                            const name_ptr_offset = pe_file.rvaToFileOffset(name_rva);

                            if (name_ptr_offset) |npo| {
                                const name_ptr = npo + 2;

                                if (name_ptr >= pe_file.data.len) {
                                    thunk_index += 1;
                                    continue;
                                }

                                const func_name = pe_file.readNullTerminatedString(name_ptr) orelse {
                                    thunk_index += 1;
                                    continue;
                                };

                                if (network_functions.has(func_name)) {
                                    callback(context, dll_name, func_name);
                                }
                            }
                        }
                        thunk_index += 1;
                    }
                }
            }
            descriptor_offset += 20;
        }
    }
};
