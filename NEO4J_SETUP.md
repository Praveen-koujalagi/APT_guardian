# Neo4j Setup Guide for APT Guardian

This guide will help you set up Neo4j for network analysis in your APT Guardian project.

## Prerequisites

- Windows 10/11
- Java 11 or later
- At least 4GB RAM available for Neo4j

## Installation Steps

### 1. Install Neo4j Desktop

1. Download Neo4j Desktop from: https://neo4j.com/download/
2. Install Neo4j Desktop following the installer prompts
3. Launch Neo4j Desktop

### 2. Create a New Database

1. In Neo4j Desktop, click "New" → "Create Project"
2. Name your project "APT Guardian"
3. Click "Add" → "Local DBMS"
4. Configure the database:
   - **Name**: `apt-guardian-db`
   - **Password**: `password` (or your preferred password)
   - **Version**: Latest Neo4j 5.x
5. Click "Create"

### 3. Start the Database

1. Click the "Start" button next to your database
2. Wait for the status to show "Active"
3. Note the connection details (should be `neo4j://127.0.0.1:7687`)

### 4. Verify Connection

1. Click "Open" → "Neo4j Browser"
2. Run this test query: `RETURN "Hello Neo4j!" as message`
3. You should see the result displayed

## Configuration for APT Guardian

### Update Connection Settings

If you used different credentials, update the connection in your code:

```python
# In utils/neo4j_network_analyzer.py, modify the default parameters:
def get_neo4j_analyzer(uri: str = "neo4j://127.0.0.1:7687", 
                      username: str = "neo4j", 
                      password: str = "your_password") -> Neo4jNetworkAnalyzer:
```

### Memory Configuration

For better performance with network data:

1. In Neo4j Desktop, click the three dots next to your database
2. Select "Settings"
3. Add these configurations:

```
# Increase memory for better performance
dbms.memory.heap.initial_size=1G
dbms.memory.heap.max_size=2G
dbms.memory.pagecache.size=1G

# Enable query logging for debugging
dbms.logs.query.enabled=true
dbms.logs.query.threshold=1s
```

4. Click "Apply" and restart the database

## Testing the Integration

### 1. Start APT Guardian

```bash
cd APT_guardian
streamlit run app.py
```

### 2. Check Neo4j Status

1. Go to the "Network Analysis" tab
2. Switch to "Live Capture Mode"
3. Check the Neo4j connection status (should show green "Connected")

### 3. Generate Test Data

Run the APT traffic generator to populate Neo4j:

```bash
python generate_apt_traffic.py
```

### 4. Verify Data in Neo4j

In Neo4j Browser, run these queries:

```cypher
// Count all hosts
MATCH (h:Host) RETURN count(h) as host_count

// Count all connections
MATCH ()-[r:CONNECTS_TO]->() RETURN count(r) as connection_count

// View network topology
MATCH (src:Host)-[r:CONNECTS_TO]->(dst:Host)
RETURN src.ip, dst.ip, r.protocol, r.port, r.packet_count
LIMIT 10
```

## Neo4j Queries for APT Detection

### Beaconing Detection
```cypher
MATCH (src:Host)-[r:CONNECTS_TO]->(dst:Host)
WHERE r.packet_count >= 10
WITH src, dst, r, 
     duration.between(r.first_seen, r.last_seen).seconds as duration_seconds
WHERE duration_seconds > 0 AND r.packet_count/duration_seconds < 0.1
RETURN src.ip, dst.ip, r.packet_count, duration_seconds
ORDER BY r.packet_count DESC
```

### Lateral Movement Detection
```cypher
MATCH (src:Host {node_type: 'internal'})-[r:CONNECTS_TO]->(dst:Host {node_type: 'internal'})
WHERE r.port IN [22, 135, 445, 3389, 5985]
WITH src, count(DISTINCT dst) as target_count, collect(DISTINCT dst.ip) as targets
WHERE target_count >= 5
RETURN src.ip, target_count, targets
ORDER BY target_count DESC
```

### Data Exfiltration Detection
```cypher
MATCH (src:Host {node_type: 'internal'})-[r:CONNECTS_TO]->(dst:Host {node_type: 'external'})
WHERE r.byte_count >= 10485760  // 10MB
RETURN src.ip, dst.ip, r.byte_count, r.protocol, r.port
ORDER BY r.byte_count DESC
```

### Port Scanning Detection
```cypher
MATCH (src:Host)-[r:CONNECTS_TO]->(dst:Host)
WITH src, dst, count(DISTINCT r.port) as unique_ports, collect(DISTINCT r.port) as ports
WHERE unique_ports >= 20
RETURN src.ip, dst.ip, unique_ports, ports[0..10] as sample_ports
ORDER BY unique_ports DESC
```

## Troubleshooting

### Connection Issues

**Problem**: "Failed to connect to Neo4j"
**Solutions**:
1. Verify Neo4j database is running (green status in Neo4j Desktop)
2. Check firewall settings allow connections to port 7687
3. Verify credentials match your database configuration

**Problem**: "Neo4j driver not available"
**Solution**: Install the Neo4j Python driver:
```bash
pip install neo4j
```

### Performance Issues

**Problem**: Slow query performance
**Solutions**:
1. Increase memory allocation in Neo4j settings
2. Create indexes on frequently queried properties:
```cypher
CREATE INDEX host_ip IF NOT EXISTS FOR (h:Host) ON (h.ip)
CREATE INDEX connection_timestamp IF NOT EXISTS FOR ()-[r:CONNECTS_TO]-() ON (r.first_seen)
```

### Data Issues

**Problem**: No data appearing in Neo4j
**Solutions**:
1. Ensure packet capture is active
2. Check that APT detector is initialized with Neo4j enabled
3. Verify network traffic is being generated

## Advanced Configuration

### Clustering (Optional)

For production deployments, consider Neo4j clustering:

1. Set up multiple Neo4j instances
2. Configure cluster discovery
3. Update connection URI to use cluster endpoints

### Backup Strategy

Set up automated backups:

1. Configure backup location in Neo4j settings
2. Set up scheduled backups using Neo4j Admin tools
3. Test restore procedures

### Monitoring

Monitor Neo4j performance:

1. Enable metrics collection
2. Use Neo4j monitoring tools
3. Set up alerts for connection issues

## Integration Benefits

With Neo4j integrated, APT Guardian provides:

- **Real-time Network Mapping**: Visualize network topology as packets flow
- **Graph-based Pattern Detection**: Detect complex attack patterns using graph queries
- **Behavioral Analysis**: Track host behavior over time with rich relationship data
- **Advanced Analytics**: Leverage graph algorithms for centrality analysis and community detection
- **Scalable Storage**: Handle large-scale network data efficiently
- **Query Flexibility**: Create custom detection rules using Cypher queries

## Next Steps

1. Explore the Network Analysis tab in the Streamlit app
2. Generate test traffic using `generate_apt_traffic.py`
3. Experiment with custom Cypher queries in Neo4j Browser
4. Monitor APT detection performance with graph-based analysis
5. Consider implementing additional graph algorithms for advanced threat detection
