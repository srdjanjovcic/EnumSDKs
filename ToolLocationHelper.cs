// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using Microsoft.Win32;
using Microsoft.Win32.Extracted;
using Microsoft.Win32.SafeHandles;
using Microsoft.Win32.SafeHandles.Extracted;

namespace EnumSDKs.Extracted
{
    internal static class ToolLocationHelper
    {
        private const string platformsFolderName = "Platforms";
        private const string uapDirectoryName = "Windows Kits";
        private const string uapRegistryName = "Windows";
        private const int uapVersion = 10;

        private static readonly object s_locker = new object();
        private static Dictionary<string, IEnumerable<TargetPlatformSDK>> s_cachedTargetPlatforms;
        private static Dictionary<string, TargetPlatformSDK> s_cachedExtensionSdks;
        private static readonly char[] s_diskRootSplitChars = { ';' };

        public static IList<TargetPlatformSDK> GetTargetPlatformSdks()
        {
            IEnumerable<TargetPlatformSDK> targetPlatforms = RetrieveTargetPlatformList();
            return targetPlatforms.Where(platform => platform.Path != null).ToList();
        }

        public static IEnumerable<string> GetPlatformsForSDK(string sdkIdentifier, Version sdkVersion)
        {
            //ErrorUtilities.VerifyThrowArgumentNull(sdkIdentifier, nameof(sdkIdentifier));
            //ErrorUtilities.VerifyThrowArgumentNull(sdkVersion, nameof(sdkVersion));

            IEnumerable<TargetPlatformSDK> targetPlatformSDKs = RetrieveTargetPlatformList();

            var platforms = new List<string>();
            foreach (TargetPlatformSDK sdk in targetPlatformSDKs)
            {
                bool isSDKMatch = string.Equals(sdk.TargetPlatformIdentifier, sdkIdentifier, StringComparison.OrdinalIgnoreCase) && Equals(sdk.TargetPlatformVersion, sdkVersion);
                if (!isSDKMatch || sdk.Platforms == null)
                {
                    continue;
                }

                foreach (string platform in sdk.Platforms.Keys)
                {
                    platforms.Add(platform);
                }
            }

            return platforms;
        }

        private static IEnumerable<TargetPlatformSDK> RetrieveTargetPlatformList()
        {
            // Get the disk and registry roots to search for sdks under
            List<string> sdkDiskRoots = GetTargetPlatformMonikerDiskRoots();
            string registryRoot = GetTargetPlatformMonikerRegistryRoots();

            string cachedTargetPlatformsKey = string.Join("|", string.Join(";", sdkDiskRoots), registryRoot);

            lock (s_locker)
            {
                if (s_cachedTargetPlatforms == null)
                {
                    s_cachedTargetPlatforms = new Dictionary<string, IEnumerable<TargetPlatformSDK>>(StringComparer.OrdinalIgnoreCase);
                }

                if (s_cachedExtensionSdks == null)
                {
                    s_cachedExtensionSdks = new Dictionary<string, TargetPlatformSDK>(StringComparer.OrdinalIgnoreCase);
                }

                if (!s_cachedTargetPlatforms.TryGetValue(cachedTargetPlatformsKey, out IEnumerable<TargetPlatformSDK> collection))
                {
                    var monikers = new Dictionary<TargetPlatformSDK, TargetPlatformSDK>();
                    GatherSDKListFromDirectory(sdkDiskRoots, monikers);
                    GatherSDKListFromRegistry(registryRoot, monikers);

                    collection = monikers.Keys.ToList();
                    s_cachedTargetPlatforms.Add(cachedTargetPlatformsKey, collection);
                }

                return collection;
            }
        }

        private static List<string> GetTargetPlatformMonikerDiskRoots()
        {
            var sdkDiskRoots = new List<string>();
            string sdkDirectoryRootsFromEnvironment = Environment.GetEnvironmentVariable("MSBUILDSDKREFERENCEDIRECTORY");
            ExtractSdkDiskRootsFromEnvironment(sdkDiskRoots, sdkDirectoryRootsFromEnvironment);
            if (sdkDiskRoots.Count == 0)
            {
                //ErrorUtilities.DebugTraceMessage("GetTargetPlatformMonikerDiskRoots", "Getting default disk roots");
                GetDefaultSDKDiskRoots(sdkDiskRoots);
            }

            //ErrorUtilities.DebugTraceMessage("GetTargetPlatformMonikerDiskRoots", "Diskroots being used '{0}'", string.Join(";", sdkDiskRoots.ToArray()));
            return sdkDiskRoots;
        }

        private static void GetDefaultSDKDiskRoots(List<string> diskRoots)
        {
            // The order is important here because we want to look in the users location first before the non privileged location.

            // We need this so that a user can also have an sdk installed in a non privileged location
            string userLocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (userLocalAppData.Length > 0)
            {
                string localAppdataFolder = Path.Combine(userLocalAppData, "Microsoft SDKs");
                if (Directory.Exists(localAppdataFolder))
                {
                    diskRoots.Add(localAppdataFolder);
                }
            }

            string defaultProgramFilesLocation = Path.Combine(
                GenerateProgramFiles32(),
                "Microsoft SDKs");
            diskRoots.Add(defaultProgramFilesLocation);
        }

        internal static string GenerateProgramFiles32()
        {
            // On a 64 bit machine we always want to use the program files x86.  If we are running as a 64 bit process then this variable will be set correctly
            // If we are on a 32 bit machine or running as a 32 bit process then this variable will be null and the programFiles variable will be correct.
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (string.IsNullOrEmpty(programFilesX86))
            {
                // 32 bit box
                programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            }

            return programFilesX86;
        }

        private static void ExtractSdkDiskRootsFromEnvironment(List<string> diskRoots, string directoryRoots)
        {
            if (diskRoots != null && !string.IsNullOrEmpty(directoryRoots))
            {
                string[] splitRoots = directoryRoots.Split(s_diskRootSplitChars, StringSplitOptions.RemoveEmptyEntries);
                //ErrorUtilities.DebugTraceMessage("ExtractSdkDiskRootsFromEnvironment", "DiskRoots from Registry '{0}'", string.Join(";", splitRoots));
                diskRoots.AddRange(splitRoots);
            }

            if (diskRoots != null)
            {
                diskRoots.ForEach(x => x = x.Trim());
                diskRoots.RemoveAll(x => !Directory.Exists(x));
            }
        }

        private static string GetTargetPlatformMonikerRegistryRoots()
        {
            //ErrorUtilities.DebugTraceMessage("GetTargetPlatformMonikerRegistryRoots", "RegistryRoot passed in '{0}'", registryRootLocation ?? string.Empty);

            string disableRegistryForSDKLookup = Environment.GetEnvironmentVariable("MSBUILDDISABLEREGISTRYFORSDKLOOKUP");
            // If we are not disabling the registry for platform sdk lookups then lets look in the default location.
            string registryRoot = string.Empty;
            if (disableRegistryForSDKLookup == null)
            {
                registryRoot = @"SOFTWARE\MICROSOFT\Microsoft SDKs\";
                //ErrorUtilities.DebugTraceMessage("GetTargetPlatformMonikerRegistryRoots", "RegistryRoot to be looked under '{0}'", registryRoot);
            }
            else
            {
                //ErrorUtilities.DebugTraceMessage("GetTargetPlatformMonikerRegistryRoots", "MSBUILDDISABLEREGISTRYFORSDKLOOKUP is set registry sdk lookup is disabled");
            }

            return registryRoot;
        }

        internal static void GatherSDKListFromDirectory(List<string> diskroots, Dictionary<TargetPlatformSDK, TargetPlatformSDK> platformSDKs)
        {
            foreach (string diskRoot in diskroots)
            {
                DirectoryInfo rootInfo = new DirectoryInfo(diskRoot);
                if (!rootInfo.Exists)
                {
                    //ErrorUtilities.DebugTraceMessage("GatherSDKListFromDirectory", "DiskRoot '{0}'does not exist, skipping it", diskRoot);
                    continue;
                }

                foreach (DirectoryInfo rootPathWithIdentifier in rootInfo.GetDirectories())
                {
                    // This makes a list of directories under the target framework identifier.
                    // This should make something like c:\Program files\Microsoft SDKs\Windows

                    if (!rootPathWithIdentifier.Exists)
                    {
                        //ErrorUtilities.DebugTraceMessage("GatherSDKListFromDirectory", "Disk root with Identifier: '{0}' does not exist. ", rootPathWithIdentifier);
                        continue;
                    }

                    //ErrorUtilities.DebugTraceMessage("GatherSDKListFromDirectory", "Disk root with Identifier: '{0}' does exist. Enumerating version folders under it. ", rootPathWithIdentifier);

                    // Get a list of subdirectories under the root path and identifier, Ie. c:\Program files\Microsoft SDKs\Windows we should see things like, V8.0, 8.0, 9.0 ect.
                    // Only grab the folders that have a version number (they can start with a v or not).

                    SortedDictionary<Version, List<string>> versionsInRoot = GatherVersionStrings(null, rootPathWithIdentifier.GetDirectories().Select<DirectoryInfo, string>(directory => directory.Name));

                    //ErrorUtilities.DebugTraceMessage("GatherSDKListFromDirectory", "Found '{0}' version folders under the identifier path '{1}'. ", versionsInRoot.Count, rootPathWithIdentifier);

                    // Go through each of the targetplatform versions under the targetplatform identifier.
                    foreach (KeyValuePair<Version, List<string>> directoryUnderRoot in versionsInRoot)
                    {
                        TargetPlatformSDK platformSDKKey;
                        if (rootPathWithIdentifier.Name.Equals(uapDirectoryName, StringComparison.OrdinalIgnoreCase) && directoryUnderRoot.Key.Major == uapVersion)
                        {
                            platformSDKKey = new TargetPlatformSDK(uapRegistryName, directoryUnderRoot.Key, null);
                        }
                        else
                        {
                            platformSDKKey = new TargetPlatformSDK(rootPathWithIdentifier.Name, directoryUnderRoot.Key, null);
                        }
                        TargetPlatformSDK targetPlatformSDK = null;

                        // DirectoryUnderRoot.Value will be a list of the raw directory strings under the targetplatform identifier directory that map to the versions specified in directoryUnderRoot.Key.
                        foreach (string version in directoryUnderRoot.Value)
                        {
                            // This should make something like c:\Program files\Microsoft SDKs\Windows\v8.0\
                            string platformSDKDirectory = Path.Combine(rootPathWithIdentifier.FullName, version);
                            string platformSDKManifest = Path.Combine(platformSDKDirectory, "SDKManifest.xml");

                            // If we are gathering the sdk platform manifests then check to see if there is a sdk manifest in the directory if not then skip over it as a platform sdk
                            bool platformSDKManifestExists = File.Exists(platformSDKManifest);
                            if (targetPlatformSDK == null && !platformSDKs.TryGetValue(platformSDKKey, out targetPlatformSDK))
                            {
                                targetPlatformSDK = new TargetPlatformSDK(platformSDKKey.TargetPlatformIdentifier, platformSDKKey.TargetPlatformVersion, platformSDKManifestExists ? platformSDKDirectory : null);
                                platformSDKs.Add(targetPlatformSDK, targetPlatformSDK);
                            }

                            if (targetPlatformSDK.Path == null && platformSDKManifestExists)
                            {
                                targetPlatformSDK.Path = platformSDKDirectory;
                            }

                            // Gather the set of platforms supported by this SDK if it's a valid one. 
                            if (!string.IsNullOrEmpty(targetPlatformSDK.Path))
                            {
                                GatherPlatformsForSdk(targetPlatformSDK);
                            }

                            // If we are passed an extension sdk dictionary we will continue to look through the extension sdk directories and try and fill it up.
                            // This should make something like c:\Program files\Microsoft SDKs\Windows\v8.0\ExtensionSDKs
                            string sdkFolderPath = Path.Combine(platformSDKDirectory, "ExtensionSDKs");
                            DirectoryInfo extensionSdksDirectory = new DirectoryInfo(sdkFolderPath);

                            if (extensionSdksDirectory.Exists)
                            {
                                GatherExtensionSDKs(extensionSdksDirectory, targetPlatformSDK);
                            }
                            else
                            {
                                //ErrorUtilities.DebugTraceMessage("GatherSDKListFromDirectory", "Could not find ExtensionsSDK folder '{0}'. ", sdkFolderPath);
                            }
                        }
                    }
                }
            }
        }

        private static void GatherSDKListFromRegistry(string registryRoot, Dictionary<TargetPlatformSDK, TargetPlatformSDK> platformMonikers)
        {
            // Setup some delegates because the methods we call use them during unit testing.
            GetRegistrySubKeyNames getSubkeyNames = new GetRegistrySubKeyNames(RegistryHelper.GetSubKeyNames);
            GetRegistrySubKeyDefaultValue getRegistrySubKeyDefaultValue = new GetRegistrySubKeyDefaultValue(RegistryHelper.GetDefaultValue);
            OpenBaseKey openBaseKey = new OpenBaseKey(RegistryHelper.OpenBaseKey);
            FileExists fileExists = new FileExists(File.Exists);

            bool is64bitOS = Environment.Is64BitOperatingSystem;
            Console.WriteLine($"is64bitOS = {is64bitOS}");

            // Under WOW64 the HKEY_CURRENT_USER\SOFTWARE key is shared. This means the values are the same in the 64 bit and 32 bit views. This means we only need to get one view of this key.
            GatherSDKsFromRegistryImpl(platformMonikers, registryRoot, RegistryView.Default, RegistryHive.CurrentUser, getSubkeyNames, getRegistrySubKeyDefaultValue, openBaseKey, fileExists);

            // Since SDKS can contain multiple architecture it makes sense to register both 32 bit and 64 bit in one location, but if for some reason that 
            // is not possible then we need to look at both hives. Choosing the 32 bit one first because is where we expect to find them usually.
            if (is64bitOS)
            {
                GatherSDKsFromRegistryImpl(platformMonikers, registryRoot, RegistryView.Registry32, RegistryHive.LocalMachine, getSubkeyNames, getRegistrySubKeyDefaultValue, openBaseKey, fileExists);
                GatherSDKsFromRegistryImpl(platformMonikers, registryRoot, RegistryView.Registry64, RegistryHive.LocalMachine, getSubkeyNames, getRegistrySubKeyDefaultValue, openBaseKey, fileExists);
            }
            else
            {
                GatherSDKsFromRegistryImpl(platformMonikers, registryRoot, RegistryView.Default, RegistryHive.LocalMachine, getSubkeyNames, getRegistrySubKeyDefaultValue, openBaseKey, fileExists);
            }
        }

        internal static void GatherSDKsFromRegistryImpl(Dictionary<TargetPlatformSDK, TargetPlatformSDK> platformMonikers, string registryKeyRoot, RegistryView registryView, RegistryHive registryHive, GetRegistrySubKeyNames getRegistrySubKeyNames, GetRegistrySubKeyDefaultValue getRegistrySubKeyDefaultValue, OpenBaseKey openBaseKey, FileExists fileExists)
        {
            Console.WriteLine();
            Console.WriteLine($"{registryView} | {registryHive} | {registryKeyRoot}");

            if (string.IsNullOrEmpty(registryKeyRoot))
            {
                return;
            }

            // Open the hive for a given view
            using (RegistryKey baseKey = openBaseKey(registryHive, registryView))
            {
                // Attach the target platform to the registry root. This should give us something like 
                // SOFTWARE\MICROSOFT\Microsoft SDKs\Windows

                // Get all of the platform identifiers
                IEnumerable<string> platformIdentifiers = getRegistrySubKeyNames(baseKey, registryKeyRoot);

                // No identifiers found.
                if (platformIdentifiers == null)
                {
                    Console.WriteLine($"  No platform identifiers found.");
                    return;
                }

                foreach (string platformIdentifier in platformIdentifiers)
                {
                    Console.WriteLine($"  - {platformIdentifier}");

                    string platformIdentifierKey = registryKeyRoot + @"\" + platformIdentifier;

                    // Get all of the version folders under the targetplatform identifier key
                    IEnumerable<string> versions = getRegistrySubKeyNames(baseKey, platformIdentifierKey);

                    // No versions found.
                    if (versions == null)
                    {
                        Console.WriteLine($"     No versions found.");
                        return;
                    }

                    Console.WriteLine($"    Versions:");
                    foreach (var v in versions)
                    {
                        Console.WriteLine($"       - {v}");
                    }

                    // Returns a a sorted set of versions and their associated registry strings. The reason we need the original strings is that
                    // they may contain a v where as a version does not support a v.
                    SortedDictionary<Version, List<string>> sortedVersions = GatherVersionStrings(null, versions);

                    Console.WriteLine($"    Sorted versions:");
                    foreach (KeyValuePair<Version, List<string>> registryVersions in sortedVersions)
                    {
                        Console.WriteLine($"       - {registryVersions.Key}");

                        TargetPlatformSDK platformSDKKey = new TargetPlatformSDK(platformIdentifier, registryVersions.Key, null);
                        TargetPlatformSDK targetPlatformSDK = null;

                        // Go through each of the raw version strings which were found in the registry
                        foreach (string version in registryVersions.Value)
                        {
                            Console.WriteLine($"         - {version}");

                            // Attach the version and extensionSDKs strings to the platformIdentifier key we built up above.
                            // Make something like SOFTWARE\MICROSOFT\Microsoft SDKs\Windows\8.0\
                            string platformSDKsRegistryKey = platformIdentifierKey + @"\" + version;

                            string platformSDKDirectory = getRegistrySubKeyDefaultValue(baseKey, platformSDKsRegistryKey);
                            Console.WriteLine($"           platformSDKDirectory = {platformSDKDirectory}");

                            // May be null because some use installationfolder instead
                            if (platformSDKDirectory == null)
                            {
                                using (RegistryKey versionKey = baseKey.OpenSubKey(platformSDKsRegistryKey))
                                {
                                    Console.WriteLine($"           versionKey = {versionKey}");
                                    if (versionKey != null)
                                    {
                                        platformSDKDirectory = versionKey.GetValue("InstallationFolder") as string;
                                        Console.WriteLine($"           platformSDKDirectory = {platformSDKDirectory}");
                                    }
                                }
                            }

                            bool platformSDKmanifestExists = false;

                            if (platformSDKDirectory != null)
                            {
                                string platformSDKManifest = Path.Combine(platformSDKDirectory, "SDKManifest.xml");
                                // Windows kits is special because they do not have an sdk manifest yet, this is for the windows sdk. We will accept them as they are. For others
                                // we will require that an sdkmanifest exists.
                                platformSDKmanifestExists = fileExists(platformSDKManifest) || platformSDKDirectory.IndexOf("Windows Kits", StringComparison.OrdinalIgnoreCase) >= 0;

                                Console.WriteLine($"           {platformSDKManifest} = {(File.Exists(platformSDKManifest) ? "Exists" : "Does not exist")}");

                            }

                            if (targetPlatformSDK == null && !platformMonikers.TryGetValue(platformSDKKey, out targetPlatformSDK))
                            {
                                targetPlatformSDK = new TargetPlatformSDK(platformSDKKey.TargetPlatformIdentifier, platformSDKKey.TargetPlatformVersion, platformSDKmanifestExists ? platformSDKDirectory : null);
                                platformMonikers.Add(targetPlatformSDK, targetPlatformSDK);
                            }

                            if (targetPlatformSDK.Path == null && platformSDKmanifestExists)
                            {
                                targetPlatformSDK.Path = platformSDKDirectory;
                            }

                            // Gather the set of platforms supported by this SDK if it's a valid one. 
                            if (!string.IsNullOrEmpty(targetPlatformSDK.Path))
                            {
                                GatherPlatformsForSdk(targetPlatformSDK);
                            }

                            // Make something like SOFTWARE\MICROSOFT\Microsoft SDKs\Windows\8.0\ExtensionSdks
                            string extensionSDKsKey = platformSDKsRegistryKey + @"\ExtensionSDKs";
                            //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Getting subkeys of '{0}'", extensionSDKsKey);

                            // Get all of the SDK name folders under the ExtensionSDKs registry key
                            IEnumerable<string> sdkNames = getRegistrySubKeyNames(baseKey, extensionSDKsKey);
                            if (sdkNames == null)
                            {
                                //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Could not find subkeys of '{0}'", extensionSDKsKey);
                                continue;
                            }

                            //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Found subkeys of '{0}'", extensionSDKsKey);

                            // For each SDK folder under ExtensionSDKs
                            foreach (string sdkName in sdkNames)
                            {
                                // Combine the SDK Name with the ExtensionSDKs key we have built up above.
                                // Make something like SOFTWARE\MICROSOFT\Windows SDKs\Windows\8.0\ExtensionSDKs\XNA
                                string sdkNameKey = extensionSDKsKey + @"\" + sdkName;

                                //Get all of the version registry keys under the SDK Name Key.
                                IEnumerable<string> sdkVersions = getRegistrySubKeyNames(baseKey, sdkNameKey);

                                //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Getting subkeys of '{0}'", sdkNameKey);
                                if (sdkVersions == null)
                                {
                                    //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Could not find subkeys of '{0}'", sdkNameKey);
                                    continue;
                                }

                                //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Found subkeys of '{0}'", sdkNameKey);

                                // For each version registry entry under the SDK Name registry key
                                foreach (string sdkVersion in sdkVersions)
                                {
                                    // We only want registry keys which parse directly to versions
                                    Version tempVersion;
                                    if (Version.TryParse(sdkVersion, out tempVersion))
                                    {
                                        string sdkDirectoryKey = sdkNameKey + @"\" + sdkVersion;
                                        //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Getting default key for '{0}'", sdkDirectoryKey);

                                        // Now that we found the registry key we need to get its default value which points to the directory this SDK is in.
                                        string directoryName = getRegistrySubKeyDefaultValue(baseKey, sdkDirectoryKey);
                                        string sdkKey = TargetPlatformSDK.GetSdkKey(sdkName, sdkVersion);
                                        if (directoryName != null)
                                        {
                                            //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "SDK installation location = '{0}'", directoryName);

                                            // Make sure the directory exists and that it has not been added before.
                                            if (!targetPlatformSDK.ExtensionSDKs.ContainsKey(sdkKey))
                                            {
                                                if (Directory.Exists(directoryName))
                                                {
                                                    string sdkManifestFileLocation = Path.Combine(directoryName, "SDKManifest.xml");
                                                    if (fileExists(sdkManifestFileLocation))
                                                    {
                                                        //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Adding SDK '{0}'  at '{1}' to the list of found sdks.", sdkKey, directoryName);
                                                        targetPlatformSDK.ExtensionSDKs.Add(sdkKey, TargetPlatformSDK.EnsureTrailingSlash(directoryName));
                                                    }
                                                    else
                                                    {
                                                        //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "No SDKManifest.xml file found at '{0}'.", sdkManifestFileLocation);
                                                    }
                                                }
                                                else
                                                {
                                                    //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "SDK directory '{0}' does not exist", directoryName);
                                                }
                                            }
                                            else
                                            {
                                                //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "SDK key was previously added. '{0}'", sdkKey);
                                            }
                                        }
                                        else
                                        {
                                            //ErrorUtilities.DebugTraceMessage("GatherSDKsFromRegistryImpl", "Default key is null for '{0}'", sdkDirectoryKey);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        private static void GatherPlatformsForSdk(TargetPlatformSDK sdk)
        {
            Console.WriteLine($"           Platforms:");

            try
            {
                string platformsRoot = Path.Combine(sdk.Path, platformsFolderName);
                Console.WriteLine($"             root = {platformsRoot}");
                DirectoryInfo platformsRootInfo = new DirectoryInfo(platformsRoot);

                Console.WriteLine($"                    exists     = {platformsRootInfo.Exists}");
                Console.WriteLine($"                    attributes = {platformsRootInfo.Attributes}");

                var fio = new FileIOPermission(FileIOPermissionAccess.Read, platformsRoot);
                try
                {
                    fio.Demand();
                    Console.WriteLine($"                    Platforms: Can read directory.");
                }
                catch (SecurityException se)
                {
                    Console.WriteLine($"                    Platforms: {se.GetType().Name}: {se.Message} {se.StackTrace}");
                }

                var fioUAP = new FileIOPermission(FileIOPermissionAccess.Read, Path.Combine(platformsRoot, "UAP"));
                try
                {
                    fioUAP.Demand();
                    Console.WriteLine($"                    Platforms\\UAP: Can read directory.");
                }
                catch (SecurityException se)
                {
                    Console.WriteLine($"                    Platforms\\UAP: {se.GetType().Name}: {se.Message} {se.StackTrace}");
                }

                CheckDirectory("                    ", platformsRoot);

                if (platformsRootInfo.Exists)
                {
                    DirectoryInfo[] platformIdentifiers = platformsRootInfo.GetDirectories();

                    Console.WriteLine($"                    numberOfDirectories = {platformIdentifiers.Length}");

                    // Iterate through all identifiers 
                    foreach (DirectoryInfo platformIdentifier in platformIdentifiers)
                    {
                        Console.WriteLine($"             - {platformIdentifier.Name}");
                        Console.WriteLine($"               exists     = {platformsRootInfo.Exists}");
                        Console.WriteLine($"               attributes = {platformsRootInfo.Attributes}");
                        CheckDirectory("               ", platformIdentifier.FullName);

                        DirectoryInfo[] platformVersions = platformIdentifier.GetDirectories();

                        Console.WriteLine($"               numberOfDirectories = {platformVersions.Length}");

                        // and all versions under each of those identifiers
                        foreach (DirectoryInfo platformVersion in platformVersions)
                        {
                            Console.WriteLine($"               - {platformVersion.Name}");
                            // If this version directory is not actually a proper version format, ignore it.
                            if (Version.TryParse(platformVersion.Name, out Version tempVersion))
                            {
                                string sdkKey = TargetPlatformSDK.GetSdkKey(platformIdentifier.Name, platformVersion.Name);
                                Console.WriteLine($"                 {sdkKey}");

                                // make sure we haven't already seen this one somehow
                                if (!sdk.Platforms.ContainsKey(sdkKey))
                                {
                                    string pathToPlatformManifest = Path.Combine(platformVersion.FullName, "Platform.xml");
                                    Console.WriteLine($"                 {pathToPlatformManifest}");
                           
                                    if (File.Exists(pathToPlatformManifest))
                                    {
                                        sdk.Platforms.Add(sdkKey, TargetPlatformSDK.EnsureTrailingSlash(platformVersion.FullName));
                                    }
                                    else
                                    {
                                        Console.WriteLine($"                   - does not exist.");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"                   - already found earlier.");
                                }
                            }
                            else
                            {
                                Console.WriteLine($"                 - failed to parse.");
                            }
                        }
                    }
                }
            }
            catch (Exception e) // when (ExceptionHandling.IsIoRelatedException(e))
            {
                Console.WriteLine($"           {e.GetType().Name}: {e.Message} {e.StackTrace}");
            }
        }

        private static void CheckDirectory(string prefix, string directory)
        {
            Console.WriteLine($"{prefix}Checking {directory}");

            Win32Native.WIN32_FIND_DATA data = default;
            string fileName = directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            int errorMode = Win32Native.SetErrorMode(1);
            try
            {
                SafeFindHandle safeFindHandle = Win32Native.FindFirstFile(fileName, ref data);
                Console.WriteLine($"{prefix}safeFindHandle.IsInvalid = {safeFindHandle.IsInvalid}");
                try
                {
                    if (safeFindHandle.IsInvalid)
                    {
                        var num = Marshal.GetLastWin32Error();
                        Console.WriteLine($"{prefix}Win32Error = {num}");
                    }
                    else
                    {
                        Console.WriteLine($"{prefix}data.cFileName           = {data.cFileName}");
                        Console.WriteLine($"{prefix}data.dwFileAttributes    = {data.dwFileAttributes}");
                        Console.WriteLine($"{prefix}data.IsFile              = {data.IsFile}");
                        Console.WriteLine($"{prefix}data.IsNormalDirectory   = {data.IsNormalDirectory}");
                        Console.WriteLine($"{prefix}data.IsRelativeDirectory = {data.IsRelativeDirectory}");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"{prefix}Reading handle: {e.GetType().Name}: {e.Message} {e.StackTrace}");
                }
                finally
                {
                    try
                    {
                        safeFindHandle.Close();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"{prefix}Closing handle: {e.GetType().Name}: {e.Message} {e.StackTrace}");
                    }
                }
            }
            finally
            {
                Win32Native.SetErrorMode(errorMode);
            }
        }

        internal static void GatherExtensionSDKs(DirectoryInfo extensionSdksDirectory, TargetPlatformSDK targetPlatformSDK)
        {
            //ErrorUtilities.DebugTraceMessage("GatherExtensionSDKs", "Found ExtensionsSDK folder '{0}'. ", extensionSdksDirectory.FullName);

            DirectoryInfo[] sdkNameDirectories = extensionSdksDirectory.GetDirectories();
            //ErrorUtilities.DebugTraceMessage("GatherExtensionSDKs", "Found '{0}' sdkName directories under '{1}'", sdkNameDirectories.Length, extensionSdksDirectory.FullName);

            // For each SDKName under the ExtensionSDKs directory
            foreach (DirectoryInfo sdkNameFolders in sdkNameDirectories)
            {
                DirectoryInfo[] sdkVersionDirectories = sdkNameFolders.GetDirectories();
                //ErrorUtilities.DebugTraceMessage("GatherExtensionSDKs", "Found '{0}' sdkVersion directories under '{1}'", sdkVersionDirectories.Length, sdkNameFolders.FullName);

                // For each Version directory under the SDK Name
                foreach (DirectoryInfo sdkVersionDirectory in sdkVersionDirectories)
                {
                    // Make sure the version folder parses to a version, anything that cannot parse directly to a version is to be ignored.
                    //ErrorUtilities.DebugTraceMessage("GatherExtensionSDKs", "Parsed sdk version folder '{0}' under '{1}'", sdkVersionDirectory.Name, sdkVersionDirectory.FullName);
                    if (Version.TryParse(sdkVersionDirectory.Name, out Version _))
                    {
                        // Create SDK name based on the folder structure. We could open the manifest here and read the display name, but that would 
                        // add complexity and since things are supposed to be in a certain structure I don't think that is needed at this point.
                        string SDKKey = TargetPlatformSDK.GetSdkKey(sdkNameFolders.Name, sdkVersionDirectory.Name);

                        // Make sure we have not added the SDK to the list of found SDKs before.
                        if (!targetPlatformSDK.ExtensionSDKs.ContainsKey(SDKKey))
                        {
                            //ErrorUtilities.DebugTraceMessage("GatherExtensionSDKs", "SDKKey '{0}' was not already found.", SDKKey);
                            string pathToSDKManifest = Path.Combine(sdkVersionDirectory.FullName, "SDKManifest.xml");
                            if (File.Exists(pathToSDKManifest))
                            {
                                targetPlatformSDK.ExtensionSDKs.Add(SDKKey, TargetPlatformSDK.EnsureTrailingSlash(sdkVersionDirectory.FullName));
                            }
                            else
                            {
                                //ErrorUtilities.DebugTraceMessage("GatherExtensionSDKs", "No SDKManifest.xml files could be found at '{0}'. Not adding sdk", pathToSDKManifest);
                            }
                        }
                        else
                        {
                            //ErrorUtilities.DebugTraceMessage("GatherExtensionSDKs", "SDKKey '{0}' was already found, not adding sdk under '{1}'", SDKKey, sdkVersionDirectory.FullName);
                        }
                    }
                    else
                    {
                        //ErrorUtilities.DebugTraceMessage("GatherExtensionSDKs", "Failed to parse sdk version folder '{0}' under '{1}'", sdkVersionDirectory.Name, sdkVersionDirectory.FullName);
                    }
                }
            }
        }

        sealed internal class ReverseVersionGenericComparer : IComparer<Version>
        {
            /// <summary>
            /// Static accessor for a ReverseVersionGenericComparer
            /// </summary>
            internal static readonly ReverseVersionGenericComparer Comparer = new ReverseVersionGenericComparer();

            /// <summary>
            /// The Compare implements a reverse comparison
            /// </summary>
            int IComparer<Version>.Compare(Version x, Version y)
            {
                // Reverse the sign of the return value.
                return y.CompareTo(x);
            }
        }

        internal static SortedDictionary<Version, List<string>> GatherVersionStrings(Version targetPlatformVersion, IEnumerable versions)
        {
            SortedDictionary<Version, List<string>> versionValues = new SortedDictionary<Version, List<string>>(ReverseVersionGenericComparer.Comparer);

            // Loop over versions from registry.
            foreach (string version in versions)
            {
                if (version.Length > 0)
                {
                    Version candidateVersion = ConvertToVersion(version, false);

                    if (candidateVersion != null && (targetPlatformVersion == null || (candidateVersion <= targetPlatformVersion)))
                    {
                        if (versionValues.TryGetValue(candidateVersion, out List<string> versionList))
                        {
                            if (!versionList.Contains(version))
                            {
                                versionList.Add(version);
                            }
                        }
                        else
                        {
                            versionValues.Add(candidateVersion, new List<string>() { version });
                        }
                    }
                }
            }

            return versionValues;
        }

        internal static Version ConvertToVersion(string version, bool throwException)
        {
            if (version.Length > 0 && (version[0] == 'v' || version[0] == 'V'))
            {
                version = version.Substring(1);
            }

            // Versions must have at least a Major and a Minor (e.g. 10.0), so if it's
            // just one number without a decimal, add a decimal and a 0. Random strings
            // like "tmp" will be filtered out in the Parse() or TryParse() steps
            if (version.IndexOf(".") == -1)
            {
                version += ".0";
            }

            Version result;
            if (throwException)
            {
                result = Version.Parse(version);
            }
            else
            {
                if (!Version.TryParse(version, out result))
                {
                    return null;
                }
            }

            return result;
        }
    }
}
