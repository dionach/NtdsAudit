namespace NtdsAudit
{
    using System;

    /// <summary>
    /// Provides helper methods for console output.
    /// </summary>
    internal static class ConsoleEx
    {
        /// <summary>
        /// Writes a message to the console with debug formatting.
        /// </summary>
        /// <param name="value">The string to write to the console.</param>
        public static void WriteDebug(FormattableString value)
        {
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine(value);
            Console.ResetColor();
        }

        /// <summary>
        /// Writes a message to the console with error formatting.
        /// </summary>
        /// <param name="value">The string to write to the console.</param>
        public static void WriteError(FormattableString value)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(value);
            Console.ResetColor();
        }

        /// <summary>
        /// Writes a message to the console with warning formatting.
        /// </summary>
        /// <param name="value">The string to write to the console.</param>
        internal static void WriteWarning(FormattableString value)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(value);
            Console.ResetColor();
        }
    }
}
