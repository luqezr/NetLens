import React, { useState, useEffect, useCallback } from 'react';
import { Box, Paper, Typography, IconButton, Chip } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { getTopology } from '../services/api';

const nodeColors = {
  router: '#e74c3c',
  switch: '#3498db',
  windows_pc: '#9b59b6',
  linux_pc: '#27ae60',
  mac: '#34495e',
  mobile: '#f39c12',
  printer: '#16a085',
  unknown: '#95a5a6',
};

const edgeColors = {
  uplink: '#e74c3c',
  lan: '#64748b',
};

function NetworkTopology() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ nodes: 0, edges: 0 });

  const fetchTopology = useCallback(async () => {
    try {
      setLoading(true);
      const response = await getTopology();
      const { nodes: nodeData, edges: edgeData } = response.data.data;

      // Transform nodes for React Flow
      const flowNodes = nodeData.map((node, index) => ({
        id: node.id,
        type: 'default',
        data: {
          label: (
            <Box sx={{ textAlign: 'center', p: 1 }}>
              <Typography variant="caption" fontWeight="bold">
                {node.label}
              </Typography>
              <br />
              <Typography variant="caption" color="text.secondary">
                {node.ip}
              </Typography>
              <br />
              <Chip
                label={node.type}
                size="small"
                sx={{
                  mt: 0.5,
                  fontSize: '0.65rem',
                  height: '18px',
                }}
              />
            </Box>
          ),
        },
        position: {
          x: (index % 5) * 250,
          y: Math.floor(index / 5) * 200,
        },
        style: {
          background: nodeColors[node.type] || nodeColors.unknown,
          color: 'white',
          border: '2px solid #fff',
          borderRadius: 8,
          padding: 10,
          width: 200,
        },
      }));

      // Transform edges for React Flow
      const flowEdges = edgeData.map((edge, index) => ({
        id: `edge-${index}`,
        source: edge.source,
        target: edge.target,
        type: 'smoothstep',
        animated: true,
        style: {
          stroke: edgeColors[edge.type] || '#64748b',
          strokeWidth: 2,
        },
        label: edge.type,
        labelStyle: {
          fill: '#0f172a',
          fontSize: 12,
        },
        labelBgStyle: {
          fill: 'rgba(255,255,255,0.9)',
          color: '#0f172a',
        },
        labelBgPadding: [6, 3],
        labelBgBorderRadius: 4,
      }));

      setNodes(flowNodes);
      setEdges(flowEdges);
      setStats({ nodes: flowNodes.length, edges: flowEdges.length });
      setLoading(false);
    } catch (error) {
      console.error('Error fetching topology:', error);
      setLoading(false);
    }
  }, [setNodes, setEdges]);

  useEffect(() => {
    fetchTopology();
  }, [fetchTopology]);

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Box>
          <Typography variant="h4" gutterBottom>
            Network Topology
          </Typography>
          <Box sx={{ display: 'flex', gap: 2 }}>
            <Chip label={`${stats.nodes} Devices`} color="primary" />
            <Chip label={`${stats.edges} Connections`} color="secondary" />
          </Box>
        </Box>
        <IconButton onClick={fetchTopology} color="primary">
          <RefreshIcon />
        </IconButton>
      </Box>

      <Paper sx={{ height: '70vh', position: 'relative' }}>
        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
            <Typography>Loading topology...</Typography>
          </Box>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
            attributionPosition="bottom-left"
          >
            <Background />
            <Controls />
            <MiniMap
              nodeColor={(node) => {
                const type = node.data.label.props.children.find(
                  (child) => child.type === Chip
                )?.props.label;
                return nodeColors[type] || nodeColors.unknown;
              }}
            />
          </ReactFlow>
        )}
      </Paper>

      <Paper sx={{ mt: 2, p: 2 }}>
        <Typography variant="h6" gutterBottom>
          Device Type Legend
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
          {Object.entries(nodeColors).map(([type, color]) => (
            <Chip
              key={type}
              label={type.replace('_', ' ')}
              sx={{ bgcolor: color, color: 'white' }}
            />
          ))}
        </Box>
      </Paper>
    </Box>
  );
}

export default NetworkTopology;
