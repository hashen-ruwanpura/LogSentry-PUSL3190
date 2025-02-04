import React, { useEffect, useState } from 'react';
import axios from 'axios';

const Logs = () => {
    const [logs, setLogs] = useState([]);

    useEffect(() => {
        axios.get('/api/dashboard/logs/')
            .then(response => setLogs(response.data))
            .catch(error => console.error(error));
    }, []);

    return (
        <div>
            <h2>Logs</h2>
            <ul>
                {logs.map(log => (
                    <li key={log.id}>{log.source}: {log.message}</li>
                ))}
            </ul>
        </div>
    );
};

export default Logs;