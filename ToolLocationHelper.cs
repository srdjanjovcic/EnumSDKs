﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace EnumSDKs
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
            return targetPlatforms.Where<TargetPlatformSDK>(platform => platform.Path != null).ToList<TargetPlatformSDK>();
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
            if (String.IsNullOrEmpty(programFilesX86))
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

        private static void GatherPlatformsForSdk(TargetPlatformSDK sdk)
        {
            //ErrorUtilities.VerifyThrow(!string.IsNullOrEmpty(sdk.Path), "SDK path must be set");

            try
            {
                string platformsRoot = Path.Combine(sdk.Path, platformsFolderName);
                DirectoryInfo platformsRootInfo = new DirectoryInfo(platformsRoot);

                if (platformsRootInfo.Exists)
                {
                    DirectoryInfo[] platformIdentifiers = platformsRootInfo.GetDirectories();
                    //ErrorUtilities.DebugTraceMessage("GatherPlatformsForSdk", "Found '{0}' platform identifier directories under '{1}'", platformIdentifiers.Length, platformsRoot);

                    // Iterate through all identifiers 
                    foreach (DirectoryInfo platformIdentifier in platformIdentifiers)
                    {
                        DirectoryInfo[] platformVersions = platformIdentifier.GetDirectories();
                        //ErrorUtilities.DebugTraceMessage("GatherPlatformsForSdk", "Found '{0}' platform version directories under '{1}'", platformVersions.Length, platformIdentifier.FullName);

                        // and all versions under each of those identifiers
                        foreach (DirectoryInfo platformVersion in platformVersions)
                        {
                            // If this version directory is not actually a proper version format, ignore it.
                            Version tempVersion;
                            if (Version.TryParse(platformVersion.Name, out tempVersion))
                            {
                                string sdkKey = TargetPlatformSDK.GetSdkKey(platformIdentifier.Name, platformVersion.Name);

                                // make sure we haven't already seen this one somehow
                                if (!sdk.Platforms.ContainsKey(sdkKey))
                                {
                                    //ErrorUtilities.DebugTraceMessage("GatherPlatformsForSdk", "SDKKey '{0}' was not already found.", sdkKey);

                                    string pathToPlatformManifest = Path.Combine(platformVersion.FullName, "Platform.xml");
                                    if (File.Exists(pathToPlatformManifest))
                                    {
                                        sdk.Platforms.Add(sdkKey, TargetPlatformSDK.EnsureTrailingSlash(platformVersion.FullName));
                                    }
                                    else
                                    {
                                        //ErrorUtilities.DebugTraceMessage("GatherPlatformsForSdk", "No Platform.xml could be found at '{0}'. Not adding this platform", pathToPlatformManifest);
                                    }
                                }
                                else
                                {
                                    //ErrorUtilities.DebugTraceMessage("GatherPlatformsForSdk", "SDKKey '{0}' was already found, not adding platform under '{1}'", sdkKey, platformVersion.FullName);
                                }
                            }
                            else
                            {
                                //ErrorUtilities.DebugTraceMessage("GatherPlatformsForSdk", "Failed to parse platform version folder '{0}' under '{1}'", platformVersion.Name, platformVersion.FullName);
                            }
                        }
                    }
                }
            }
            catch (Exception) // when (ExceptionHandling.IsIoRelatedException(e))
            {
                //ErrorUtilities.DebugTraceMessage("GatherPlatformsForSdk", "Encountered exception trying to gather platform-specific data: {0}", e.Message);
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