import React, { useEffect, useState } from 'react';
import axios from 'axios';

const Incidents = () => {
    const [incidents, setIncidents] = useState([]);

    useEffect(() => {
        axios.get('/api/dashboard/incidents/')
            .then(response => setIncidents(response.data))
            .catch(error => console.error(error));
    }, []);

    return (
        <div>
            <h2>Incidents</h2>
            <ul>
                {incidents.map(incident => (
                    <li key={incident.id}>{incident.name}: {incident.description}</li>
                ))}
            </ul>
        </div>
    );
};

export default Incidents;