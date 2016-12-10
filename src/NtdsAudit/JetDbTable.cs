namespace NtdsAudit
{
    using System;
    using System.Collections.Generic;
    using Microsoft.Isam.Esent.Interop;

    /// <summary>
    /// Wraps access to a Jet table in <see cref="IDisposable"/>.
    /// </summary>
    internal class JetDbTable : IDisposable
    {
        private readonly JET_DBID _dbid;
        private readonly JET_SESID _sesid;
        private readonly JET_TABLEID _tableid;

        private bool _disposedValue = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="JetDbTable"/> class.
        /// </summary>
        /// <param name="sesid">The database session to use.</param>
        /// <param name="dbid">The database to open the table in.</param>
        /// <param name="tablename">The name of the table to open.</param>
        public JetDbTable(JET_SESID sesid, JET_DBID dbid, string tablename)
        {
            _sesid = sesid;
            _dbid = dbid;

            Api.JetOpenTable(_sesid, _dbid, tablename, null, 0, OpenTableGrbit.ReadOnly | OpenTableGrbit.Sequential, out _tableid);
        }

        /// <summary>
        /// Creates a dictionary which maps column names to their column IDs.
        /// </summary>
        /// <returns>A dictionary mapping column names to column IDs.</returns>
        public IDictionary<string, JET_COLUMNID> GetColumnDictionary()
        {
            return Api.GetColumnDictionary(_sesid, _tableid);
        }

        /// <summary>
        /// Position the cursor before the first record in the table. A subsequent move next will position the cursor on the first record.
        /// </summary>
        public void MoveBeforeFirst()
        {
            Api.MoveBeforeFirst(_sesid, _tableid);
        }

        /// <summary>
        /// Retrieves columns into <see cref="ColumnValue"/> objects.
        /// </summary>
        /// <param name="values">The values to retrieve.</param>
        public void RetrieveColumns(params ColumnValue[] values)
        {
            Api.RetrieveColumns(_sesid, _tableid, values);
        }

        /// <summary>
        /// Try to move to the next record in the table. If there is not a next record this returns false, if a different error is encountered an exception is thrown.
        /// </summary>
        /// <returns>True if the move was successful.</returns>
        public bool TryMoveNext()
        {
            return Api.TryMoveNext(_sesid, _tableid);
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
                    Api.JetCloseTable(_sesid, _tableid);
                }

                _disposedValue = true;
            }
        }
    }
}
