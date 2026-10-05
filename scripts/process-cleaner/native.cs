using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

public static class ProcessCleanerNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicInfo
    {
        public IntPtr ExitStatus, Peb, Affinity, Priority, Id, ParentId;
    }
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate int QueryInfo(IntPtr process, int kind, out BasicInfo info, int size, out int length);
    private delegate bool WindowCallback(IntPtr window, IntPtr state);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern IntPtr OpenProcess(uint access, bool inherit, uint id);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi)] private static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] buffer, UIntPtr length, out UIntPtr read);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool DuplicateHandle(IntPtr source, IntPtr handle, IntPtr target, out IntPtr duplicate, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool IsWow64Process(IntPtr process, out bool wow64);
    [DllImport("kernel32.dll")] private static extern IntPtr GetStdHandle(int kind);
    [DllImport("kernel32.dll")] private static extern uint GetFileType(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool PeekNamedPipe(IntPtr handle, IntPtr buffer, uint size, IntPtr read, out uint available, IntPtr remaining);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError=true)] private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint timeout);
    [DllImport("user32.dll")] private static extern bool EnumWindows(WindowCallback callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr window, WindowCallback callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint id);

    private static IntPtr ReadPointer(IntPtr process, IntPtr address)
    {
        byte[] bytes = new byte[8];
        UIntPtr count;
        if (!ReadProcessMemory(process, address, bytes, (UIntPtr)8, out count) || count.ToUInt64() != 8)
            throw new InvalidOperationException("Cannot read process handle metadata");
        return new IntPtr(BitConverter.ToInt64(bytes, 0));
    }

    // The internal layout is checked against all three handles of this process.
    // Unsupported layouts and 32-bit processes fail closed.
    private static IntPtr Parameters(IntPtr process, uint expectedId)
    {
        bool wow64;
        if (IntPtr.Size != 8 || !IsWow64Process(process, out wow64) || wow64)
            throw new InvalidOperationException("Unsupported process architecture");
        IntPtr address = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationProcess");
        if (address == IntPtr.Zero) throw new InvalidOperationException("Query unavailable");
        QueryInfo query = (QueryInfo)Marshal.GetDelegateForFunctionPointer(address, typeof(QueryInfo));
        BasicInfo info;
        int length;
        if (query(process, 0, out info, Marshal.SizeOf(typeof(BasicInfo)), out length) != 0 || info.Id.ToInt64() != expectedId || info.Peb == IntPtr.Zero)
            throw new InvalidOperationException("Cannot identify process metadata");
        return ReadPointer(process, IntPtr.Add(info.Peb, 0x20));
    }

    public static bool LayoutSupported()
    {
        try
        {
            IntPtr process = GetCurrentProcess();
            IntPtr parameters = Parameters(process, (uint)System.Diagnostics.Process.GetCurrentProcess().Id);
            for (int i = 0; i < 3; i++)
            {
                IntPtr handle = GetStdHandle(-10 - i);
                if (handle == IntPtr.Zero || handle == new IntPtr(-1) || ReadPointer(process, IntPtr.Add(parameters, 0x20 + i * 8)) != handle)
                    return false;
            }
            return true;
        }
        catch { return false; }
    }

    public static string InputState(uint id, long expectedCreation)
    {
        if (!LayoutSupported()) return "Unknown";
        IntPtr process = OpenProcess(0x450, false, id);
        if (process == IntPtr.Zero) return "Unknown";
        IntPtr duplicate = IntPtr.Zero;
        try
        {
            long creation, exit, kernel, user;
            if (!GetProcessTimes(process, out creation, out exit, out kernel, out user) || creation != expectedCreation) return "Changed";
            IntPtr parameters = Parameters(process, id);
            IntPtr input = ReadPointer(process, IntPtr.Add(parameters, 0x20));
            if (input == IntPtr.Zero || input == new IntPtr(-1) || !DuplicateHandle(process, input, GetCurrentProcess(), out duplicate, 0, false, 2)) return "Unknown";
            if (GetFileType(duplicate) != 3) return "NotPipe";
            IntPtr owned = duplicate;
            duplicate = IntPtr.Zero;
            Task<string> check = Task.Run(() => {
                try
                {
                    uint available;
                    if (PeekNamedPipe(owned, IntPtr.Zero, 0, IntPtr.Zero, out available, IntPtr.Zero)) return "Connected";
                    return Marshal.GetLastWin32Error() == 109 ? "Disconnected" : "Unknown";
                }
                finally { CloseHandle(owned); }
            });
            return check.Wait(1000) ? check.Result : "Unknown";
        }
        catch { return "Unknown"; }
        finally
        {
            if (duplicate != IntPtr.Zero) CloseHandle(duplicate);
            CloseHandle(process);
        }
    }

    public static long[] Times(uint id)
    {
        IntPtr process = OpenProcess(0x1000, false, id);
        if (process == IntPtr.Zero) return null;
        try
        {
            long creation, exit, kernel, user;
            return GetProcessTimes(process, out creation, out exit, out kernel, out user) ? new long[] { creation, kernel + user } : null;
        }
        finally { CloseHandle(process); }
    }

    public static uint[] VisibleProcessIds()
    {
        HashSet<uint> result = new HashSet<uint>();
        WindowCallback visit = (window, state) => {
            uint id;
            if (IsWindowVisible(window)) { GetWindowThreadProcessId(window, out id); result.Add(id); }
            return true;
        };
        if (!EnumWindows((window, state) => { visit(window, state); EnumChildWindows(window, visit, state); return true; }, IntPtr.Zero))
            throw new InvalidOperationException("Cannot enumerate visible windows");
        uint[] ids = new uint[result.Count];
        result.CopyTo(ids);
        return ids;
    }

    // Identity comparison and termination use the same open process handle.
    public static bool TerminateExact(uint id, long expectedCreation)
    {
        IntPtr process = OpenProcess(0x101001, false, id);
        if (process == IntPtr.Zero) return false;
        try
        {
            long creation, exit, kernel, user;
            if (!GetProcessTimes(process, out creation, out exit, out kernel, out user) || creation != expectedCreation) return false;
            return TerminateProcess(process, 0) && WaitForSingleObject(process, 2000) == 0;
        }
        finally { CloseHandle(process); }
    }
}
