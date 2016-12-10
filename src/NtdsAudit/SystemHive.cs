namespace NtdsAudit
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using Registry;
    using static System.FormattableString;

    /// <summary>
    /// Provides methods for extracting the system key.
    /// </summary>
    internal static class SystemHive
    {
        private static readonly byte[] SYSTEMKEYTRANSFORMS = new byte[] { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };

        /// <summary>
        /// Extracts the system key from a SYSTEM registry hive.
        /// </summary>
        /// <param name="systemHivePath">The file path of the SYSTEM registry hive.</param>
        /// <returns>A byte array containing the 16 byte system key.</returns>
        public static byte[] LoadSystemKeyFromHive(string systemHivePath)
        {
            systemHivePath = systemHivePath ?? throw new ArgumentNullException(nameof(systemHivePath));

            // Load the registry hive
            var hive = new RegistryHiveOnDemand(systemHivePath);

            // Get the current control set version from the hive
            var currentControlSetVersion = int.Parse(hive.GetKey("Select").Values[0].ValueData, CultureInfo.InvariantCulture);

            // Get the class name of the four subkeys in which the sytem key is stored, and convert to hex to get the scrambled system key
            var scrambledKeyList = new List<byte>();

            foreach (var keyName in new string[] { "JD", "Skew1", "GBG", "Data" })
            {
                var key = hive.GetKey(Invariant($"ControlSet00{currentControlSetVersion}\\Control\\Lsa\\{keyName}"));
                var className = key.ClassName;
                scrambledKeyList.AddRange(Enumerable.Range(0, className.Length / 2).Select(x => Convert.ToByte(className.Substring(x * 2, 2), 16)).ToArray());
            }

            var scrambledKey = scrambledKeyList.ToArray();

            // Unscramble the system key based on the known transforms
            var systemKeyList = new List<byte>();

            for (var i = 0; i < scrambledKey.Length; i++)
            {
                systemKeyList.Add(scrambledKey[SYSTEMKEYTRANSFORMS[i]]);
            }

            return systemKeyList.ToArray();
        }
    }
}
