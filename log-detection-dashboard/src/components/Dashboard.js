import React from 'react';
import Threats from './Threats';
import Incidents from './Incidents';
import Logs from './Logs';

const Dashboard = () => {
    return (
        <div>
            <h1>Dashboard</h1>
            <Threats />
            <Incidents />
            <Logs />
        </div>
    );
};

export default Dashboard;