using System;

namespace EnumSDKs
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var platformSDKs = ToolLocationHelperCopy.GetTargetPlatformSdks();
            foreach (var sdk in platformSDKs)
            {
                Console.WriteLine($"{sdk.TargetPlatformIdentifier} - {sdk.TargetPlatformVersion}");
                var  platforms = ToolLocationHelperCopy.GetPlatformsForSDK(sdk.TargetPlatformIdentifier, sdk.TargetPlatformVersion);
                foreach (string platform in platforms)
                {
                    Console.WriteLine($"\t{platform}");
                }
            }

            Console.WriteLine("Done!");
            Console.ReadKey();
        }
    }
}
