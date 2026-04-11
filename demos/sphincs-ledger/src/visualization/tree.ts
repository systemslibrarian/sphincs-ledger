// Merkle tree SVG visualization
// Renders a simplified Merkle tree (up to 4 levels, 16 leaves) as SVG
// Each node displays truncated hash. Authentication path highlighted in amber.

import type { MerkleNode } from '../crypto/merkle';

const NODE_RADIUS = 20;
const LEVEL_HEIGHT = 80;
const ANIM_DELAY = 150;

interface NodePosition {
  x: number;
  y: number;
  node: MerkleNode;
}

function collectPositions(
  node: MerkleNode,
  x: number,
  y: number,
  spread: number,
  positions: NodePosition[]
): void {
  positions.push({ x, y, node });
  if (node.left) {
    collectPositions(node.left, x - spread, y + LEVEL_HEIGHT, spread / 2, positions);
  }
  if (node.right) {
    collectPositions(node.right, x + spread, y + LEVEL_HEIGHT, spread / 2, positions);
  }
}

export function renderMerkleTree(
  container: HTMLElement,
  root: MerkleNode,
  highlightPath?: string[],
  selectedLeafHash?: string,
): void {
  container.innerHTML = '';

  // Compute tree depth
  let depth = 0;
  let n = root;
  while (n.left) { n = n.left; depth++; }

  const width = Math.max(600, Math.pow(2, depth) * 60);
  const height = (depth + 1) * LEVEL_HEIGHT + 60;

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.style.display = 'block';
  svg.style.margin = '0 auto';

  const isLight = document.documentElement.getAttribute('data-theme') === 'light';

  const positions: NodePosition[] = [];
  collectPositions(root, width / 2, 40, width / 4, positions);

  const highlightSet = new Set(highlightPath ?? []);
  if (selectedLeafHash) highlightSet.add(selectedLeafHash);

  // Draw edges first
  for (const pos of positions) {
    if (pos.node.left) {
      const leftPos = positions.find((p) => p.node === pos.node.left)!;
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', String(pos.x));
      line.setAttribute('y1', String(pos.y));
      line.setAttribute('x2', String(leftPos.x));
      line.setAttribute('y2', String(leftPos.y));
      const bothHighlighted = highlightSet.has(pos.node.hash) && highlightSet.has(pos.node.left.hash);
      line.setAttribute('stroke', bothHighlighted ? '#f59e0b' : (isLight ? '#94a3b8' : '#444'));
      line.setAttribute('stroke-width', bothHighlighted ? '3' : '1.5');
      svg.appendChild(line);
    }
    if (pos.node.right) {
      const rightPos = positions.find((p) => p.node === pos.node.right)!;
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('x1', String(pos.x));
      line.setAttribute('y1', String(pos.y));
      line.setAttribute('x2', String(rightPos.x));
      line.setAttribute('y2', String(rightPos.y));
      const bothHighlighted = highlightSet.has(pos.node.hash) && highlightSet.has(pos.node.right.hash);
      line.setAttribute('stroke', bothHighlighted ? '#f59e0b' : (isLight ? '#94a3b8' : '#444'));
      line.setAttribute('stroke-width', bothHighlighted ? '3' : '1.5');
      svg.appendChild(line);
    }
  }

  // Draw nodes
  for (const pos of positions) {
    const isHighlighted = highlightSet.has(pos.node.hash);

    const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    group.style.cursor = 'pointer';

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', String(pos.x));
    circle.setAttribute('cy', String(pos.y));
    circle.setAttribute('r', String(NODE_RADIUS));
    circle.setAttribute('fill', isHighlighted ? '#f59e0b' : (pos.node.isLeaf ? '#3b82f6' : '#6366f1'));
    circle.setAttribute('stroke', isLight ? '#e2e8f0' : '#1e1e2e');
    circle.setAttribute('stroke-width', '2');

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', String(pos.x));
    text.setAttribute('y', String(pos.y + 4));
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', isHighlighted ? '#000' : '#fff');
    text.setAttribute('font-size', '9');
    text.setAttribute('font-family', 'monospace');
    text.textContent = pos.node.hash.substring(0, 8);

    // Tooltip on hover
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = pos.node.hash;
    group.appendChild(title);

    group.appendChild(circle);
    group.appendChild(text);
    svg.appendChild(group);
  }

  container.appendChild(svg);
}

export async function animateAuthPath(
  container: HTMLElement,
  root: MerkleNode,
  authPath: string[],
  leafHash: string,
  intermediates: string[]
): Promise<void> {
  // First render without highlighting
  renderMerkleTree(container, root);

  // Then highlight nodes one by one
  const allHighlighted: string[] = [];
  for (let i = 0; i < intermediates.length; i++) {
    allHighlighted.push(intermediates[i]);
    if (i < authPath.length) {
      allHighlighted.push(authPath[i]);
    }
    renderMerkleTree(container, root, allHighlighted, leafHash);
    await new Promise((resolve) => setTimeout(resolve, ANIM_DELAY));
  }
}
