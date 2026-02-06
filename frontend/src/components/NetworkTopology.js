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
import DeviceDetailDialog from './DeviceDetailDialog';

const nodeColors = {
  router: '#e74c3c',
  switch: '#3498db',
  server: '#64748b',
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

function normalizeTypeKey(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) return 'unknown';
  if (s === 'router' || s.includes('gateway')) return 'router';
  if (s === 'switch') return 'switch';
  if (s.includes('printer')) return 'printer';
  if (s.includes('server') || s.includes('nas')) return 'server';
  if (s.includes('windows')) return 'windows_pc';
  if (s.includes('linux') || s.includes('ubuntu') || s.includes('debian') || s.includes('fedora')) return 'linux_pc';
  if (s === 'mac' || s.includes('macos') || s.includes('os x') || s.includes('apple')) return 'mac';
  if (s.includes('phone') || s.includes('mobile') || s.includes('android') || s.includes('iphone') || s.includes('ipad') || s.includes('tablet')) return 'mobile';

  // Common formatting variants -> snake-ish key
  const key = s.replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
  return key || 'unknown';
}

function isValidIpv4(ip) {
  if (!ip || typeof ip !== 'string') return false;
  if (ip.includes('/')) return false;
  const m = ip.match(/^([0-9]{1,3}\.){3}[0-9]{1,3}$/);
  if (!m) return false;
  const parts = ip.split('.').map((p) => Number(p));
  return parts.length === 4 && parts.every((n) => Number.isFinite(n) && n >= 0 && n <= 255);
}

function computeHierarchyPositions(nodeData, edgeData) {
  const byId = new Map((nodeData || []).map((n) => [n.id, n]));
  const incoming = new Map();
  const outgoing = new Map();
  for (const e of edgeData || []) {
    if (!incoming.has(e.target)) incoming.set(e.target, []);
    if (!outgoing.has(e.source)) outgoing.set(e.source, []);
    incoming.get(e.target).push(e.source);
    outgoing.get(e.source).push(e.target);
  }

  const routers = (nodeData || []).filter((n) => n.type === 'router');
  const switches = (nodeData || []).filter((n) => n.type === 'switch');
  const devices = (nodeData || []).filter((n) => n.type !== 'router' && n.type !== 'switch');

  const nodeWidth = 220;
  const xGap = 80;
  const yGap = 190;

  const routerY = 0;
  const switchY = routerY + yGap;
  const deviceY = switchY + yGap;

  // Determine parent router for each switch (incoming edge from a router)
  const switchToRouter = new Map();
  for (const sw of switches) {
    const srcs = incoming.get(sw.id) || [];
    const routerSrc = srcs.find((s) => byId.get(s)?.type === 'router');
    if (routerSrc) switchToRouter.set(sw.id, routerSrc);
  }

  // Determine parent switch for each device (incoming edge from a switch)
  const deviceToSwitch = new Map();
  for (const d of devices) {
    const srcs = incoming.get(d.id) || [];
    const swSrc = srcs.find((s) => byId.get(s)?.type === 'switch');
    if (swSrc) deviceToSwitch.set(d.id, swSrc);
  }

  // If there's exactly one switch, attach orphan devices to it.
  if (switches.length === 1) {
    for (const d of devices) {
      if (!deviceToSwitch.has(d.id)) deviceToSwitch.set(d.id, switches[0].id);
    }
  }

  // Group switches under routers.
  const routerIds = routers.map((r) => r.id);
  const routerToSwitches = new Map(routerIds.map((id) => [id, []]));
  for (const sw of switches) {
    const rId = switchToRouter.get(sw.id) || (routers[0]?.id ?? null);
    if (rId) {
      if (!routerToSwitches.has(rId)) routerToSwitches.set(rId, []);
      routerToSwitches.get(rId).push(sw.id);
    }
  }

  const positions = {};

  // Place routers in a row.
  const routerRow = routers.length > 0 ? routers : (switches.length > 0 ? [] : devices);
  const routerCount = routerRow.length || 1;
  const routerRowWidth = routerCount * nodeWidth + (routerCount - 1) * xGap;

  for (let i = 0; i < routerRow.length; i += 1) {
    const n = routerRow[i];
    const x = -routerRowWidth / 2 + i * (nodeWidth + xGap);
    const y = n.type === 'router' ? routerY : routerY;
    positions[n.id] = { x, y };
  }

  // Place switches under their router.
  for (const r of routers) {
    const swIds = routerToSwitches.get(r.id) || [];
    if (swIds.length === 0) continue;
    const rPos = positions[r.id] || { x: 0, y: routerY };
    const width = swIds.length * nodeWidth + (swIds.length - 1) * xGap;
    for (let i = 0; i < swIds.length; i += 1) {
      const swId = swIds[i];
      const x = rPos.x - width / 2 + i * (nodeWidth + xGap);
      positions[swId] = { x, y: switchY };
    }
  }

  // Place switches not assigned to routers.
  const unplacedSwitches = switches.filter((s) => !positions[s.id]);
  if (unplacedSwitches.length > 0) {
    const width = unplacedSwitches.length * nodeWidth + (unplacedSwitches.length - 1) * xGap;
    for (let i = 0; i < unplacedSwitches.length; i += 1) {
      const sw = unplacedSwitches[i];
      positions[sw.id] = { x: -width / 2 + i * (nodeWidth + xGap), y: switchY };
    }
  }

  // Group devices under switches.
  const switchToDevices = new Map(switches.map((s) => [s.id, []]));
  for (const d of devices) {
    const swId = deviceToSwitch.get(d.id);
    if (swId) {
      if (!switchToDevices.has(swId)) switchToDevices.set(swId, []);
      switchToDevices.get(swId).push(d.id);
    }
  }

  // Place devices under each switch.
  for (const sw of switches) {
    const devIds = switchToDevices.get(sw.id) || [];
    if (devIds.length === 0) continue;
    const swPos = positions[sw.id] || { x: 0, y: switchY };
    const cols = Math.min(4, Math.max(1, devIds.length));
    const rowWidth = cols * nodeWidth + (cols - 1) * xGap;
    for (let idx = 0; idx < devIds.length; idx += 1) {
      const col = idx % cols;
      const row = Math.floor(idx / cols);
      const x = swPos.x - rowWidth / 2 + col * (nodeWidth + xGap);
      const y = deviceY + row * (yGap * 0.9);
      positions[devIds[idx]] = { x, y };
    }
  }

  // Place orphan devices if any.
  const orphanDevices = devices.filter((d) => !positions[d.id]);
  if (orphanDevices.length > 0) {
    const width = orphanDevices.length * nodeWidth + (orphanDevices.length - 1) * xGap;
    for (let i = 0; i < orphanDevices.length; i += 1) {
      positions[orphanDevices[i].id] = { x: -width / 2 + i * (nodeWidth + xGap), y: deviceY };
    }
  }

  // Place any remaining nodes (defensive).
  for (const n of nodeData || []) {
    if (!positions[n.id]) positions[n.id] = { x: 0, y: deviceY };
  }

  return positions;
}

function NetworkTopology() {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ nodes: 0, edges: 0 });
  const [detailOpen, setDetailOpen] = useState(false);
  const [selectedDeviceIp, setSelectedDeviceIp] = useState(null);

  const closeDetails = useCallback(() => {
    setDetailOpen(false);
    setSelectedDeviceIp(null);
  }, []);

  const onNodeClick = useCallback((_, node) => {
    const ip = node?.data?.ip;
    if (!isValidIpv4(ip)) return;
    setSelectedDeviceIp(ip);
    setDetailOpen(true);
  }, []);

  const fetchTopology = useCallback(async () => {
    try {
      setLoading(true);
      const response = await getTopology();
      const { nodes: nodeData, edges: edgeData } = response.data.data;

      const positions = computeHierarchyPositions(nodeData, edgeData);

      // Transform nodes for React Flow
      const flowNodes = nodeData.map((node) => {
        const typeKey = normalizeTypeKey(node.type);
        return {
          id: node.id,
          type: 'default',
          data: {
            ip: node.ip,
            type: node.type,
            label: (
              <Box sx={{ textAlign: 'center', p: 1, cursor: isValidIpv4(node.ip) ? 'pointer' : 'default' }}>
                <Typography variant="caption" fontWeight="bold" sx={{ textDecoration: isValidIpv4(node.ip) ? 'underline' : 'none' }}>
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
          position: positions[node.id] || { x: 0, y: 0 },
          style: {
            background: nodeColors[typeKey] || nodeColors.unknown,
            color: 'white',
            border: '2px solid #fff',
            borderRadius: 8,
            padding: 10,
            width: 200,
          },
        };
      });

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
            onNodeClick={onNodeClick}
            fitView
            attributionPosition="bottom-left"
          >
            <Background />
            <Controls />
            <MiniMap
              nodeColor={(node) => {
                const type = node?.data?.type;
                return nodeColors[type] || nodeColors.unknown;
              }}
            />
          </ReactFlow>
        )}
      </Paper>

      <DeviceDetailDialog
        open={detailOpen}
        onClose={closeDetails}
        deviceIp={selectedDeviceIp}
      />

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
