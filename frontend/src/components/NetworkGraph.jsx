import React, { useRef, useMemo, useEffect, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Text, Html } from '@react-three/drei';
import * as THREE from 'three';

const TRUST_COLORS = {
  critical: '#00ff88',
  high: '#44aaff',
  medium: '#ffaa00',
  low: '#ff6600',
  untrusted: '#ff2244',
};

function DeviceNode({ device, position, isSelected, onClick }) {
  const meshRef = useRef();
  const [hovered, setHovered] = useState(false);

  const color = TRUST_COLORS[device.trust_level] || '#888888';
  const size = 0.4 + (device.open_port_count * 0.05);
  const isHighRisk = device.risk_score >= 0.6;

  useFrame((state) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += 0.005;
      if (isSelected) {
        meshRef.current.scale.setScalar(1 + Math.sin(state.clock.elapsedTime * 2) * 0.1);
      }
    }
  });

  return (
    <group position={position}>
      {/* Glow effect */}
      <mesh>
        <sphereGeometry args={[size * 1.5, 16, 16]} />
        <meshBasicMaterial
          color={color}
          transparent
          opacity={isSelected ? 0.15 : hovered ? 0.1 : 0.05}
        />
      </mesh>

      {/* Main sphere */}
      <mesh
        ref={meshRef}
        onClick={(e) => { e.stopPropagation(); onClick(device); }}
        onPointerOver={() => setHovered(true)}
        onPointerOut={() => setHovered(false)}
      >
        <sphereGeometry args={[size, 32, 32]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={isSelected ? 0.5 : hovered ? 0.3 : 0.1}
          metalness={0.3}
          roughness={0.4}
        />
      </mesh>

      {/* High-risk indicator */}
      {isHighRisk && (
        <mesh>
          <ringGeometry args={[size * 1.2, size * 1.4, 32]} />
          <meshBasicMaterial
            color="#ff2244"
            transparent
            opacity={0.6}
            side={THREE.DoubleSide}
          />
        </mesh>
      )}

      {/* Label */}
      <Html
        position={[0, -size - 0.3, 0]}
        center
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.2s',
        }}
      >
        <div
          style={{
            color: '#fff',
            fontSize: '10px',
            fontFamily: 'JetBrains Mono, monospace',
            background: 'rgba(0,0,0,0.7)',
            padding: '2px 6px',
            borderRadius: '4px',
            border: `1px solid ${color}`,
            whiteSpace: 'nowrap',
            opacity: hovered || isSelected ? 1 : 0.7,
          }}
        >
          {device.hostname.length > 15
            ? device.hostname.slice(0, 12) + '...'
            : device.hostname}
        </div>
      </Html>
    </group>
  );
}

function ConnectionLine({ start, end, riskScore, isActive }) {
  const ref = useRef();

  const color = riskScore > 0.7 ? '#ff2244' : riskScore > 0.4 ? '#ffaa00' : '#44aaff';
  const opacity = isActive ? 0.6 : 0.15;

  useEffect(() => {
    if (ref.current) {
      const points = [new THREE.Vector3(...start), new THREE.Vector3(...end)];
      ref.current.geometry.dispose();
      ref.current.geometry = new THREE.BufferGeometry().setFromPoints(points);
    }
  }, [start, end]);

  return (
    <line ref={ref}>
      <bufferGeometry />
      <lineBasicMaterial
        color={color}
        transparent
        opacity={opacity}
        linewidth={1}
      />
    </line>
  );
}

function ParticleField() {
  const particlesRef = useRef();
  const count = 200;

  const positions = useMemo(() => {
    const pos = new Float32Array(count * 3);
    for (let i = 0; i < count * 3; i++) {
      pos[i] = (Math.random() - 0.5) * 30;
    }
    return pos;
  }, []);

  useFrame((state) => {
    if (particlesRef.current) {
      particlesRef.current.rotation.y = state.clock.elapsedTime * 0.02;
    }
  });

  return (
    <points ref={particlesRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={count}
          array={positions}
          itemSize={3}
        />
      </bufferGeometry>
      <pointsMaterial
        size={0.03}
        color="#44aaff"
        transparent
        opacity={0.4}
        sizeAttenuation
      />
    </points>
  );
}

export default function NetworkGraph({ devices, connections, onDeviceSelect, selectedDevice }) {
  const nodePositions = useMemo(() => {
    if (!devices || devices.length === 0) return {};

    const positions = {};
    const center = [0, 0, 0];
    const radius = Math.max(4, devices.length * 0.8);

    // Arrange in a 3D sphere layout
    devices.forEach((device, i) => {
      const phi = Math.acos(-1 + (2 * i + 1) / devices.length);
      const theta = Math.sqrt(devices.length * Math.PI) * phi;

      // Cluster by trust level
      const trustOffset = {
        critical: 0.5,
        high: 0.8,
        medium: 1.0,
        low: 1.3,
        untrusted: 1.5,
      }[device.trust_level] || 1.0;

      const r = radius * trustOffset;

      positions[device.ip] = [
        center[0] + r * Math.sin(phi) * Math.cos(theta),
        center[1] + r * Math.cos(phi),
        center[2] + r * Math.sin(phi) * Math.sin(theta),
      ];
    });

    return positions;
  }, [devices]);

  const safeDevices = devices || [];
  const safeConnections = connections || [];

  return (
    <div className="network-graph-container">
      <Canvas
        camera={{ position: [8, 6, 10], fov: 50 }}
        gl={{ antialias: true, alpha: true }}
        onPointerMissed={() => onDeviceSelect(null)}
      >
        <ambientLight intensity={0.3} />
        <pointLight position={[10, 10, 10]} intensity={0.8} color="#44aaff" />
        <pointLight position={[-10, -10, -10]} intensity={0.4} color="#ff44aa" />

        <fog attach="fog" args={['#0a0a1a', 15, 25]} />

        <ParticleField />

        {/* Connection lines */}
        {safeConnections.map((conn, i) => {
          const start = nodePositions[conn.source_ip];
          const end = nodePositions[conn.target_ip];
          if (!start || !end) return null;
          return (
            <ConnectionLine
              key={`conn-${i}`}
              start={start}
              end={end}
              riskScore={conn.risk_score}
              isActive={
                (selectedDevice && conn.source_ip === selectedDevice.ip) ||
                (selectedDevice && conn.target_ip === selectedDevice.ip)
              }
            />
          );
        })}

        {/* Device nodes */}
        {safeDevices.map((device) => {
          const pos = nodePositions[device.ip];
          if (!pos) return null;
          return (
            <DeviceNode
              key={device.ip}
              device={device}
              position={pos}
              isSelected={selectedDevice?.ip === device.ip}
              onClick={onDeviceSelect}
            />
          );
        })}

        <OrbitControls
          enableDamping
          dampingFactor={0.05}
          rotateSpeed={0.5}
          minDistance={3}
          maxDistance={25}
        />
      </Canvas>

      {safeDevices.length === 0 && (
        <div className="graph-overlay">
          <div className="graph-placeholder">
            <div className="placeholder-icon">🌐</div>
            <h3>No Network Map Yet</h3>
            <p>Start a scan to discover devices and visualize your network's zero-trust posture in 3D.</p>
          </div>
        </div>
      )}
    </div>
  );
}
