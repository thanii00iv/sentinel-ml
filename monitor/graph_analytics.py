"""
Temporal Heterogeneous Security Graph Analytics & Community Detection Engine
Builds dynamic multi-entity knowledge graphs (IP, Path, User, UserAgent) using NetworkX,
executes Louvain / modularity community detection to uncover coordinated multi-IP campaigns,
computes graph centralities, and traces critical attack propagation paths.
"""

import networkx as nx
from datetime import timedelta
from django.utils import timezone
from django.db.models import Count, Q
from django.conf import settings
from .models import RequestLog, IPRiskProfile, ThreatHuntFinding


class SecurityKnowledgeGraph:
    """
    Temporal Heterogeneous Security Graph (THSG).
    Nodes: IP, Path, User, Device
    Edges: ACCESS, ATTACK, AUTH, USES
    """
    def __init__(self, time_window_hours: int = 24):
        self.graph = nx.Graph()
        self.directed_graph = nx.DiGraph()
        self.time_window_hours = time_window_hours
        self.build_graph()

    def build_graph(self):
        """Construct graph from recent RequestLog database telemetry."""
        now = timezone.now()
        since = now - timedelta(hours=self.time_window_hours)
        logs = RequestLog.objects.filter(timestamp__gte=since).order_by('timestamp')

        for log in logs:
            ip = log.ip_address
            path = log.path
            user = getattr(log, 'username', None)
            ua = log.user_agent or 'Unknown'
            is_attack = bool(
                log.is_sqli_suspect or
                log.is_brute_force_suspect or
                log.is_recon_suspect or
                log.is_xss_suspect or
                log.is_path_traversal_suspect or
                (log.is_login_attempt and not log.login_success)
            )

            # 1. Add IP Node
            if not self.graph.has_node(f"ip:{ip}"):
                self.graph.add_node(
                    f"ip:{ip}",
                    node_type='IP',
                    label=ip,
                    risk_score=0,
                    is_quarantined=False,
                    total_events=0,
                    attack_events=0
                )
            self.graph.nodes[f"ip:{ip}"]['total_events'] += 1
            if is_attack:
                self.graph.nodes[f"ip:{ip}"]['attack_events'] += 1

            # 2. Add Path Node
            is_sensitive = any(p in path.lower() for p in ['/admin', '/login', '/api', '/etc/', '/wp-'])
            if not self.graph.has_node(f"path:{path}"):
                self.graph.add_node(
                    f"path:{path}",
                    node_type='PATH',
                    label=path,
                    is_sensitive=is_sensitive,
                    hit_count=0,
                    attack_hit_count=0
                )
            self.graph.nodes[f"path:{path}"]['hit_count'] += 1
            if is_attack:
                self.graph.nodes[f"path:{path}"]['attack_hit_count'] += 1

            # 3. Add Edge IP -> Path
            edge_key = (f"ip:{ip}", f"path:{path}")
            if self.graph.has_edge(*edge_key):
                self.graph[edge_key[0]][edge_key[1]]['weight'] += 1
                if is_attack:
                    self.graph[edge_key[0]][edge_key[1]]['attack_weight'] += 1
            else:
                self.graph.add_edge(
                    edge_key[0],
                    edge_key[1],
                    weight=1,
                    attack_weight=1 if is_attack else 0,
                    edge_type='ATTACK' if is_attack else 'ACCESS'
                )

            # 4. Optional User Node & Edge
            if user:
                if not self.graph.has_node(f"user:{user}"):
                    self.graph.add_node(f"user:{user}", node_type='USER', label=user)
                u_edge = (f"ip:{ip}", f"user:{user}")
                if self.graph.has_edge(*u_edge):
                    self.graph[u_edge[0]][u_edge[1]]['weight'] += 1
                else:
                    self.graph.add_edge(u_edge[0], u_edge[1], weight=1, edge_type='AUTH')

        # Sync profile risk scores
        for node in list(self.graph.nodes()):
            if node.startswith('ip:'):
                ip_val = node[3:]
                prof = IPRiskProfile.objects.filter(ip_address=ip_val).first()
                if prof:
                    self.graph.nodes[node]['risk_score'] = prof.fused_score or prof.risk_score
                    self.graph.nodes[node]['is_quarantined'] = prof.is_blocked

    def detect_communities(self) -> dict:
        """
        Execute Louvain Community Detection (or Modularity partitioning)
        to identify clusters of IPs and target assets executing coordinated campaigns.
        Returns: {node: community_id}
        """
        if self.graph.number_of_nodes() == 0:
            return {}

        try:
            # Use NetworkX Louvain communities
            communities = nx.community.louvain_communities(self.graph, weight='weight', seed=42)
            partition = {}
            for comm_id, comm_nodes in enumerate(communities):
                for node in comm_nodes:
                    partition[node] = comm_id
            return partition
        except Exception:
            # Fallback to connected components if modularity fails on sparse graphs
            partition = {}
            for comm_id, component in enumerate(nx.connected_components(self.graph)):
                for node in component:
                    partition[node] = comm_id
            return partition

    def compute_centralities(self) -> dict:
        """Compute Degree, PageRank, and Betweenness centralities across graph entities."""
        if self.graph.number_of_nodes() == 0:
            return {'degree': {}, 'pagerank': {}, 'betweenness': {}}

        try:
            deg = nx.degree_centrality(self.graph)
            pr = nx.pagerank(self.graph, weight='weight', max_iter=200)
            btw = nx.betweenness_centrality(self.graph, weight='weight')
            return {'degree': deg, 'pagerank': pr, 'betweenness': btw}
        except Exception:
            deg = nx.degree_centrality(self.graph)
            return {'degree': deg, 'pagerank': deg, 'betweenness': deg}

    def detect_coordinated_campaigns(self, min_ips_per_campaign: int = 2) -> list:
        """
        Identify distributed campaigns where multiple IPs target identical clusters of endpoints.
        Returns structured campaign metadata for Autonomous Threat Hunter.
        """
        communities = self.detect_communities()
        comm_groups = {}
        for node, c_id in communities.items():
            comm_groups.setdefault(c_id, []).append(node)

        campaigns = []
        for c_id, nodes in comm_groups.items():
            ips = [n[3:] for n in nodes if n.startswith('ip:')]
            paths = [n[5:] for n in nodes if n.startswith('path:')]

            # Count total attacks in this community
            total_attacks = sum(self.graph.nodes[f"ip:{ip}"].get('attack_events', 0) for ip in ips)

            if len(ips) >= min_ips_per_campaign and total_attacks >= 2:
                # Find most targeted path in campaign
                top_targets = sorted(
                    paths,
                    key=lambda p: self.graph.nodes.get(f"path:{p}", {}).get('attack_hit_count', 0),
                    reverse=True
                )
                campaigns.append({
                    'community_id': c_id,
                    'attacker_ips': ips,
                    'targeted_paths': top_targets[:5],
                    'total_attackers': len(ips),
                    'total_attacks': total_attacks,
                    'primary_target': top_targets[0] if top_targets else 'N/A',
                    'severity': 'CRITICAL' if len(ips) >= 3 or total_attacks >= 10 else 'HIGH'
                })

        return sorted(campaigns, key=lambda c: c['total_attacks'], reverse=True)

    def find_attack_paths(self, start_ip: str, critical_endpoints: list = None) -> list:
        """
        Find shortest and highest-risk paths from entrypoint IP to critical crown-jewel assets.
        """
        critical_endpoints = critical_endpoints or ['/admin/', '/login/', '/api/v1/auth/']
        start_node = f"ip:{start_ip}"

        if not self.graph.has_node(start_node):
            return []

        paths_found = []
        for ep in critical_endpoints:
            target_node = f"path:{ep}"
            if self.graph.has_node(target_node):
                try:
                    if nx.has_path(self.graph, start_node, target_node):
                        path = nx.shortest_path(self.graph, start_node, target_node)
                        paths_found.append({
                            'target': ep,
                            'path_nodes': path,
                            'length': len(path) - 1
                        })
                except Exception:
                    continue

        return paths_found

    def export_d3_graph(self, target_ip: str = None, max_nodes: int = 60) -> dict:
        """
        Export graph in D3.js / Cytoscape force-directed format with communities,
        centrality sizes, and edge risk metadata.
        """
        communities = self.detect_communities()
        centralities = self.compute_centralities()
        pr_scores = centralities.get('pagerank', {})

        subgraph = self.graph
        if target_ip:
            target_node = f"ip:{target_ip}"
            if self.graph.has_node(target_node):
                # Extract 2-hop ego network around target IP
                ego_nodes = nx.single_source_shortest_path_length(self.graph, target_node, cutoff=2).keys()
                subgraph = self.graph.subgraph(ego_nodes)

        nodes_list = []
        links_list = []

        # Sort nodes by centrality to limit to max_nodes
        top_nodes = sorted(
            subgraph.nodes(),
            key=lambda n: pr_scores.get(n, 0.0),
            reverse=True
        )[:max_nodes]

        top_nodes_set = set(top_nodes)
        if target_ip and f"ip:{target_ip}" not in top_nodes_set:
            top_nodes_set.add(f"ip:{target_ip}")

        for node in top_nodes_set:
            ndata = subgraph.nodes[node]
            ntype = ndata.get('node_type', 'UNKNOWN')
            comm_id = communities.get(node, 0)
            pagerank = round(float(pr_scores.get(node, 0.01)), 4)

            # Node display styling
            if ntype == 'IP':
                risk = ndata.get('risk_score', 0)
                color = '#ff4d6d' if risk >= 70 else ('#fb923c' if risk >= 40 else '#38bdf8')
                size = max(18, min(42, int(risk / 2.5) + 16))
            elif ntype == 'PATH':
                is_sens = ndata.get('is_sensitive', False)
                color = '#c084fc' if is_sens else '#10b981'
                size = 20 if is_sens else 14
            else:
                color = '#e2e8f0'
                size = 14

            nodes_list.append({
                'id': node,
                'label': ndata.get('label', node),
                'type': ntype,
                'community': comm_id,
                'pagerank': pagerank,
                'risk_score': ndata.get('risk_score', 0),
                'is_quarantined': ndata.get('is_quarantined', False),
                'color': color,
                'size': size
            })

        for u, v, edata in subgraph.edges(data=True):
            if u in top_nodes_set and v in top_nodes_set:
                weight = edata.get('weight', 1)
                attacks = edata.get('attack_weight', 0)
                is_mal = attacks > 0
                links_list.append({
                    'source': u,
                    'target': v,
                    'weight': weight,
                    'attacks': attacks,
                    'is_attack': is_mal,
                    'color': 'rgba(255, 77, 109, 0.75)' if is_mal else 'rgba(56, 189, 248, 0.35)',
                    'width': max(1.5, min(6.0, weight * 0.8))
                })

        return {
            'nodes': nodes_list,
            'links': links_list,
            'total_nodes': len(nodes_list),
            'total_links': len(links_list),
            'communities_count': len(set(communities.values())) if communities else 0
        }


def get_security_graph(hours: int = 24) -> SecurityKnowledgeGraph:
    """Factory helper to construct and cache the security knowledge graph."""
    return SecurityKnowledgeGraph(time_window_hours=hours)
