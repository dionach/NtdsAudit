namespace NtdsAudit
{
    using System;
    using System.Text;
    using System.Threading;

    /// <summary>
    /// An ASCII progress bar
    /// Based on https://gist.github.com/DanielSWolf/0ab6a96899cc5377bf54
    /// Code is under the MIT License
    /// </summary>
    public class ProgressBar : IDisposable, IProgress<double>
    {
        private const string Animation = @"|/-\";
        private const int BlockCount = 10;
        private readonly TimeSpan _animationInterval = TimeSpan.FromSeconds(1.0 / 8);
        private readonly object _lock = new object();
        private readonly string _text;
        private readonly Timer _timer;
        private int _animationIndex = 0;
        private double _currentProgress = 0;
        private string _currentText = string.Empty;

        private bool _disposedValue = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="ProgressBar"/> class.
        /// </summary>
        public ProgressBar()
            : this(string.Empty)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ProgressBar"/> class.
        /// </summary>
        /// <param name="text">The text to prepend to the progress bar.</param>
        public ProgressBar(string text)
        {
            _text = text;
            _timer = new Timer(TimerHandler);

            // A progress bar is only for temporary display in a console window.
            // If the console output is redirected to a file, draw nothing.
            // Otherwise, we'll end up with a lot of garbage in the target file.
            if (!Console.IsOutputRedirected)
            {
                ResetTimer();
            }
        }

        /// <summary>
        /// Implements the <see cref="IDisposable"/> pattern.
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Updates the progress percentage.
        /// </summary>
        /// <param name="value">The percentage of progress to display.</param>
        public void Report(double value)
        {
            // Make sure value is in [0..1] range
            value = Math.Max(0, Math.Min(1, value));
            Interlocked.Exchange(ref _currentProgress, value);
        }

        /// <summary>
        /// Implements the <see cref="IDisposable"/> pattern.
        /// </summary>
        /// <param name="disposing">A value indicating whether the <see cref="IDisposable"/> is currently disposing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    lock (_lock)
                    {
                        UpdateText(string.Empty);
                        _timer.Dispose();
                    }
                }

                _disposedValue = true;
            }
        }

        private void ResetTimer()
        {
            _timer.Change(_animationInterval, TimeSpan.FromMilliseconds(-1));
        }

        private void TimerHandler(object state)
        {
            lock (_lock)
            {
                if (_disposedValue)
                {
                    return;
                }

                int progressBlockCount = (int)(_currentProgress * BlockCount);
                int percent = (int)(_currentProgress * 100);
                string text = string.Format(
                    "{0} [{1}{2}] {3,4}% {4}",
                    _text,
                    new string('#', progressBlockCount),
                    new string('-', BlockCount - progressBlockCount),
                    percent,
                    Animation[_animationIndex++ % Animation.Length]);
                UpdateText(text);

                ResetTimer();
            }
        }

        private void UpdateText(string text)
        {
            // Get length of common portion
            int commonPrefixLength = 0;
            int commonLength = Math.Min(_currentText.Length, text.Length);
            while (commonPrefixLength < commonLength && text[commonPrefixLength] == _currentText[commonPrefixLength])
            {
                commonPrefixLength++;
            }

            // Backtrack to the first differing character
            StringBuilder outputBuilder = new StringBuilder();
            outputBuilder.Append('\b', _currentText.Length - commonPrefixLength);

            // Output new suffix
            outputBuilder.Append(text.Substring(commonPrefixLength));

            // If the new text is shorter than the old one: delete overlapping characters
            int overlapCount = _currentText.Length - text.Length;
            if (overlapCount > 0)
            {
                outputBuilder.Append(' ', overlapCount);
                outputBuilder.Append('\b', overlapCount);
            }

            Console.Write(outputBuilder);
            _currentText = text;
        }

        // To detect redundant calls
    }
}
