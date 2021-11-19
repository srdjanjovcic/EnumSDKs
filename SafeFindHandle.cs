#region Assembly mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
// C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.7.2\mscorlib.dll
// Decompiled with ICSharpCode.Decompiler 6.1.0.5902
#endregion

using Microsoft.Win32.Extracted;
using System.Security;

namespace Microsoft.Win32.SafeHandles.Extracted
{
    [SecurityCritical]
    internal sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        [SecurityCritical]
        internal SafeFindHandle()
            : base(ownsHandle: true)
        {
        }

        [SecurityCritical]
        protected override bool ReleaseHandle()
        {
            return Win32Native.FindClose(handle);
        }
    }
}
#if false // Decompilation log
'9' items in cache
#endif
