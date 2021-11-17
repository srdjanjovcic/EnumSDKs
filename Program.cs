using System;
using EnumSDKs.Extracted;

namespace EnumSDKs
{
    internal class Program
    {
        static void Main()
        {
            var platformSDKs = ToolLocationHelper.GetTargetPlatformSdks();

            Console.WriteLine();
            foreach (var sdk in platformSDKs)
            {
                Console.WriteLine($"{sdk.TargetPlatformIdentifier} - {sdk.TargetPlatformVersion}");
                var  platforms = ToolLocationHelper.GetPlatformsForSDK(sdk.TargetPlatformIdentifier, sdk.TargetPlatformVersion);
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
