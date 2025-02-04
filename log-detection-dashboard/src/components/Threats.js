import React, { useEffect, useState } from 'react';
import axios from 'axios';

const Threats = () => {
    const [threats, setThreats] = useState([]);

    useEffect(() => {
        axios.get('/api/dashboard/threats/')
            .then(response => setThreats(response.data))
            .catch(error => console.error(error));
    }, []);

    return (
        <div>
            <h2>Threats</h2>
            <ul>
                {threats.map(threat => (
                    <li key={threat.id}>{threat.name}: {threat.description}</li>
                ))}
            </ul>
        </div>
    );
};

export default Threats;