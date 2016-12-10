namespace NtdsAudit
{
    using System;
    using Microsoft.Isam.Esent.Interop;

    /// <summary>
    /// Wraps access to a Jet database in <see cref="IDisposable"/>.
    /// </summary>
    internal class JetDb : IDisposable
    {
        private JET_DBID _dbid;
        private bool _disposedValue = false;
        private JET_INSTANCE _instance;
        private JET_SESID _sesid;

        /// <summary>
        /// Initializes a new instance of the <see cref="JetDb"/> class.
        /// </summary>
        /// <param name="dbPath">The database to open.</param>
        public JetDb(string dbPath)
        {
            dbPath = dbPath ?? throw new ArgumentNullException(nameof(dbPath));

            // Set the correct database page size for NTDS
            Api.JetGetDatabaseFileInfo(dbPath, out int pageSize, JET_DbInfo.PageSize);
            Api.JetSetSystemParameter(JET_INSTANCE.Nil, JET_SESID.Nil, JET_param.DatabasePageSize, pageSize, null);

            // Turn off recovery mode
            Api.JetSetSystemParameter(JET_INSTANCE.Nil, JET_SESID.Nil, JET_param.Recovery, null, "Off");

            // Create the ESENT instance
            Api.JetCreateInstance(out _instance, Guid.NewGuid().ToString());

            // Set JET_param.CircularLog to 1 so that ESENT will automatically delete unneeded log files
            Api.JetSetSystemParameter(_instance, JET_SESID.Nil, JET_param.CircularLog, 1, null);

            // Initialise ESENT. JetInit will inspect the logfiles to see if the last shutdown was clean
            // If it wasn't (e.g. the application crashed) recovery will be run automatically bringing the database to a consistent state
            Api.JetInit(ref _instance);

            // Create the ESENT session
            Api.JetBeginSession(_instance, out _sesid, null, null);

            // Attach NTDS database as read only
            Api.JetAttachDatabase(_sesid, dbPath, AttachDatabaseGrbit.ReadOnly);

            // Open NTDS database as read only
            Api.JetOpenDatabase(_sesid, dbPath, null, out _dbid, OpenDatabaseGrbit.ReadOnly);
        }

        /// <summary>
        /// Opens a Jet table using <see cref="JetDbTable"/>.
        /// </summary>
        /// <param name="tableName">The name of the table to open.</param>
        /// <returns>The <see cref="JetDbTable"/>.</returns>
        public JetDbTable OpenJetDbTable(string tableName)
        {
            return new JetDbTable(_sesid, _dbid, tableName);
        }

        /// <summary>
        /// Implements the <see cref="IDisposable"/> pattern.
        /// </summary>
        void IDisposable.Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
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
                    // Dispose managed state (managed objects).

                    // End the ESENT session.
                    Api.JetEndSession(_sesid, EndSessionGrbit.None);

                    // Terminate the ESENT instance, performing a clean shutdown.
                    Api.JetTerm(_instance);
                }

                _disposedValue = true;
            }
        }
    }
}
