// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using Microsoft.Win32;

namespace EnumSDKs.Extracted
{
    internal delegate RegistryKey OpenBaseKey(RegistryHive hive, RegistryView view);
    internal delegate IEnumerable<string> GetRegistrySubKeyNames(RegistryKey baseKey, string subKey);
    internal delegate string GetRegistrySubKeyDefaultValue(RegistryKey baseKey, string subKey);
    internal delegate bool FileExists(string path);
}
