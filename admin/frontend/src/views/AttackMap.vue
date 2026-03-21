<template>
  <div class="attack-map-page">
    <!-- Header -->
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2 class="h4 mb-0">攻击地图</h2>
      <div class="d-flex align-items-center gap-2">
        <span v-if="lastUpdated" class="text-muted small mr-2">更新于 {{ lastUpdated }}</span>
        <button class="btn btn-sm btn-outline-secondary" @click="loadData" :disabled="loading">
          <i class="bi bi-arrow-clockwise mr-1" :class="{ 'spin': loading }"></i>刷新
        </button>
        <div class="btn-group btn-group-sm">
          <button
            v-for="opt in filterOptions" :key="opt.value"
            class="btn"
            :class="filter === opt.value ? 'btn-primary' : 'btn-outline-secondary'"
            @click="filter = opt.value; loadData()"
          >{{ opt.label }}</button>
        </div>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="row mb-4">
      <div class="col-6 col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body py-3">
            <div class="text-muted small mb-1">拦截攻击</div>
            <div class="h3 mb-0 text-danger">{{ stats.total_blocked || 0 }}</div>
          </div>
        </div>
      </div>
      <div class="col-6 col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body py-3">
            <div class="text-muted small mb-1">攻击 IP 数</div>
            <div class="h3 mb-0 text-warning">{{ stats.unique_attacker_ips || 0 }}</div>
          </div>
        </div>
      </div>
      <div class="col-6 col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body py-3">
            <div class="text-muted small mb-1">来源国家</div>
            <div class="h3 mb-0 text-info">{{ stats.countries || 0 }}</div>
          </div>
        </div>
      </div>
      <div class="col-6 col-md-3 mb-3">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-body py-3">
            <div class="text-muted small mb-1">拦截率</div>
            <div class="h3 mb-0 text-success">{{ stats.block_rate || 0 }}%</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Map + Tables -->
    <div class="row">
      <!-- Map -->
      <div class="col-12 mb-4">
        <div class="card border-0 shadow-sm">
          <div class="card-body p-0 position-relative">
            <div v-if="loading && !chartReady" class="map-placeholder d-flex align-items-center justify-content-center">
              <div class="text-center text-muted">
                <div class="spinner-border spinner-border-sm mb-2" role="status"></div>
                <div class="small">正在解析 IP 地理位置...</div>
              </div>
            </div>
            <div v-show="!loading || chartReady" ref="mapEl" class="map-canvas"></div>
          </div>
        </div>
      </div>

      <!-- Top IPs Table -->
      <div class="col-md-6 mb-4">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-header bg-white border-bottom-0 pt-3 pb-0">
            <h6 class="mb-0"><i class="bi bi-fire text-danger mr-1"></i>Top 攻击 IP</h6>
          </div>
          <div class="card-body p-0">
            <div v-if="!topIps.length" class="text-center text-muted py-4 small">暂无数据</div>
            <table v-else class="table table-sm table-hover mb-0">
              <thead class="thead-light">
                <tr>
                  <th>#</th>
                  <th>IP 地址</th>
                  <th>国家/城市</th>
                  <th class="text-right">攻击次数</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(item, idx) in topIps" :key="item.ip">
                  <td class="text-muted">{{ idx + 1 }}</td>
                  <td>
                    <code class="small">{{ item.ip }}</code>
                  </td>
                  <td class="small text-muted">{{ item.country }}<span v-if="item.city">, {{ item.city }}</span></td>
                  <td class="text-right">
                    <span class="badge badge-danger">{{ item.count }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Top Countries Table -->
      <div class="col-md-6 mb-4">
        <div class="card border-0 shadow-sm h-100">
          <div class="card-header bg-white border-bottom-0 pt-3 pb-0">
            <h6 class="mb-0"><i class="bi bi-globe text-primary mr-1"></i>Top 来源国家</h6>
          </div>
          <div class="card-body p-0">
            <div v-if="!topCountries.length" class="text-center text-muted py-4 small">暂无数据</div>
            <table v-else class="table table-sm table-hover mb-0">
              <thead class="thead-light">
                <tr>
                  <th>#</th>
                  <th>国家</th>
                  <th>占比</th>
                  <th class="text-right">攻击次数</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(item, idx) in topCountries" :key="item.country">
                  <td class="text-muted">{{ idx + 1 }}</td>
                  <td class="small">{{ item.country }}</td>
                  <td style="min-width:80px">
                    <div class="progress" style="height:6px; margin-top:4px;">
                      <div
                        class="progress-bar bg-primary"
                        :style="{ width: countryPct(item.count) + '%' }"
                      ></div>
                    </div>
                  </td>
                  <td class="text-right">
                    <span class="badge badge-primary">{{ item.count }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import axios from 'axios';
import moment from 'moment';
import { getApiErrorMessage, shouldHandleLocally } from '../utils/http';

const ECHARTS_CDN = 'https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js';
const WORLD_MAP_CDN = 'https://cdn.jsdelivr.net/npm/echarts@5.4.3/map/js/world.js';

// Server location (where attacks point TO). Adjustable.
const SERVER_LOC = [116.4, 39.9]; // Beijing as default

function loadScript(src) {
  return new Promise((resolve, reject) => {
    if (document.querySelector(`script[src="${src}"]`)) return resolve();
    const s = document.createElement('script');
    s.src = src;
    s.onload = resolve;
    s.onerror = reject;
    document.head.appendChild(s);
  });
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function hexToRgb(hex) {
  const normalized = String(hex || '').replace('#', '');
  if (normalized.length !== 6) {
    return [255, 255, 255];
  }
  return [
    parseInt(normalized.slice(0, 2), 16),
    parseInt(normalized.slice(2, 4), 16),
    parseInt(normalized.slice(4, 6), 16),
  ];
}

function rgbToHex([r, g, b]) {
  return `#${[r, g, b].map((item) => clamp(Math.round(item), 0, 255).toString(16).padStart(2, '0')).join('')}`;
}

function mixColor(startHex, endHex, ratio) {
  const start = hexToRgb(startHex);
  const end = hexToRgb(endHex);
  const t = clamp(ratio, 0, 1);
  return rgbToHex(start.map((item, index) => item + (end[index] - item) * t));
}

export default {
  name: 'AttackMap',
  data() {
    return {
      loading: false,
      chartReady: false,
      chart: null,
      echartsLoaded: false,
      lastUpdated: '',
      filter: 'blocked',
      filterOptions: [
        { label: '仅拦截', value: 'blocked' },
        { label: '全部', value: 'all' },
      ],
      stats: {
        total_blocked: 0,
        unique_attacker_ips: 0,
        countries: 0,
        block_rate: 0,
      },
      points: [],
      topIps: [],
      topCountries: [],
      refreshTimer: null,
    };
  },
  computed: {
    totalCountryAttacks() {
      return this.topCountries.reduce((s, c) => s + c.count, 0);
    },
  },
  async mounted() {
    await this.initEcharts();
    await this.loadData();
    this.refreshTimer = setInterval(() => this.loadData(), 30000);
  },
  beforeDestroy() {
    clearInterval(this.refreshTimer);
    if (this.chart) {
      this.chart.dispose();
      this.chart = null;
    }
  },
  methods: {
    countryPct(count) {
      if (!this.totalCountryAttacks) return 0;
      return Math.round((count / this.totalCountryAttacks) * 100);
    },

    async initEcharts() {
      if (this.echartsLoaded) return;
      try {
        await loadScript(ECHARTS_CDN);
        await loadScript(WORLD_MAP_CDN);
        this.echartsLoaded = true;
      } catch (e) {
        this.$toast.error('地图资源加载失败，请检查网络连接');
      }
    },

    async loadData() {
      if (this.loading) return;
      this.loading = true;
      try {
        const onlyBlocked = this.filter === 'blocked';
        const [mapRes, statsRes] = await Promise.all([
          axios.get('/map/attack-data', { params: { limit: 500, only_blocked: onlyBlocked } }),
          axios.get('/map/stats', { params: { only_blocked: onlyBlocked } }),
        ]);

        const mapData = mapRes.data.data || {};
        const statsData = statsRes.data.data || {};

        this.points = mapData.points || [];
        this.topIps = (mapData.stats && mapData.stats.top_ips) || [];
        this.topCountries = (mapData.stats && mapData.stats.top_countries) || [];

        this.stats = {
          total_blocked: statsData.total_blocked || 0,
          unique_attacker_ips: statsData.unique_attacker_ips || 0,
          countries: (mapData.stats && mapData.stats.countries) || 0,
          block_rate: statsData.block_rate || 0,
        };

        this.lastUpdated = moment().format('HH:mm:ss');
        this.renderMap();
      } catch (e) {
        if (shouldHandleLocally(e)) {
          this.$toast.error(getApiErrorMessage(e, '加载攻击地图数据失败'));
        }
      } finally {
        this.loading = false;
      }
    },

    renderMap() {
      if (!this.echartsLoaded || typeof window.echarts === 'undefined') return;

      const el = this.$refs.mapEl;
      if (!el) return;

      if (!this.chart) {
        this.chart = window.echarts.init(el, 'dark');
        this.chartReady = true;
        window.addEventListener('resize', this.resizeChart);
      }

      const countryCountMap = new Map();
      this.points.forEach((point) => {
        const country = point && point.country ? String(point.country) : '';
        if (!country || country === 'Unknown') {
          return;
        }
        countryCountMap.set(country, (countryCountMap.get(country) || 0) + (Number(point.count) || 0));
      });

      // Build scatter data
      const scatterData = this.points.map(p => ({
        name: `${p.ip}\n${p.country}${p.city ? ', ' + p.city : ''}\n攻击 ${p.count} 次`,
        value: [p.lon, p.lat, p.count],
        ip: p.ip,
        country: p.country,
      }));

      // Build lines (attack source -> server)
      const linesData = this.points
        .filter(p => p.count >= 1)
        .slice(0, 80) // limit visual clutter
        .map(p => ({
          coords: [[p.lon, p.lat], SERVER_LOC],
          lineStyle: { color: p.count > 5 ? '#ff4d4f' : '#faad14', opacity: Math.min(0.15 + p.count * 0.05, 0.8) },
        }));

      // Max count for bubble scaling
      const maxCount = this.points.reduce((m, p) => Math.max(m, p.count), 1);
      const maxCountryCount = Array.from(countryCountMap.values()).reduce((m, count) => Math.max(m, count), 1);
      const countryRegions = Array.from(countryCountMap.entries()).map(([country, count]) => {
        const heat = count / maxCountryCount;
        return {
          name: country,
          itemStyle: {
            areaColor: mixColor('#18324d', '#ff5b4d', heat),
            borderColor: heat > 0.7 ? '#ffd166' : '#294e78',
            borderWidth: heat > 0.7 ? 1.2 : 0.7
          },
          emphasis: {
            itemStyle: {
              areaColor: mixColor('#244566', '#ff8369', Math.min(1, heat + 0.15))
            }
          }
        };
      });

      const option = {
        backgroundColor: '#0d1117',
        title: {
          text: '全球攻击来源热力与入站路径',
          left: 18,
          top: 14,
          textStyle: {
            color: '#e5edf7',
            fontSize: 16,
            fontWeight: 700
          },
          subtext: `来源国家 ${countryCountMap.size} · 攻击源 ${this.points.length} · 最近更新 ${this.lastUpdated || '-'}`,
          subtextStyle: {
            color: '#89a3bf',
            fontSize: 11
          }
        },
        tooltip: {
          trigger: 'item',
          formatter: (params) => {
            if (params.componentSubType === 'map') {
              const value = Number(params.value || 0);
              return `<b>${params.name}</b><br/>攻击次数: <b>${value}</b>`;
            }
            if (params.seriesType === 'effectScatter' || params.seriesType === 'scatter') {
              const [,, count] = params.value;
              return `<b>${params.data.ip}</b><br/>${params.data.country}<br/>攻击次数: <b>${count}</b>`;
            }
            return '';
          },
        },
        geo: {
          map: 'world',
          roam: true,
          zoom: 1.2,
          center: [10, 20],
          label: { show: false },
          regions: countryRegions,
          itemStyle: {
            areaColor: '#12263f',
            borderColor: '#1e3a5f',
            borderWidth: 0.5,
          },
          emphasis: {
            itemStyle: { areaColor: '#1a3a5c' },
            label: { show: false },
          },
        },
        series: [
          {
            name: '国家热度',
            type: 'map',
            map: 'world',
            roam: false,
            silent: true,
            geoIndex: 0,
            emphasis: { disabled: true },
            data: Array.from(countryCountMap.entries()).map(([country, count]) => ({
              name: country,
              value: count
            }))
          },
          // Flight lines
          {
            name: '攻击路径',
            type: 'lines',
            coordinateSystem: 'geo',
            zlevel: 1,
            effect: {
              show: true,
              period: 4.5,
              trailLength: 0.22,
              symbol: 'arrow',
              symbolSize: 5,
              color: '#ff4d4f',
            },
            lineStyle: {
              color: '#ff6b6b',
              width: 1,
              curveness: 0.28,
              opacity: 0.22,
            },
            data: linesData,
          },
          // Attack source bubbles
          {
            name: '攻击来源',
            type: 'effectScatter',
            coordinateSystem: 'geo',
            zlevel: 2,
            rippleEffect: {
              brushType: 'stroke',
              scale: 4,
              period: 3,
            },
            symbolSize: (val) => {
              const count = val[2] || 1;
              return Math.max(6, Math.min(30, 6 + (count / maxCount) * 24));
            },
            itemStyle: {
              color: (params) => {
                const count = params.value[2] || 1;
                if (count > 10) return '#ff4d4f';
                if (count > 3) return '#fa8c16';
                return '#fadb14';
              },
              opacity: 0.85,
              shadowBlur: 18,
              shadowColor: 'rgba(255, 107, 107, 0.45)',
            },
            data: scatterData,
            tooltip: { show: true },
          },
          // Server location marker
          {
            name: '服务器',
            type: 'scatter',
            coordinateSystem: 'geo',
            zlevel: 3,
            symbol: 'pin',
            symbolSize: 20,
            itemStyle: {
              color: '#52c41a',
              shadowBlur: 14,
              shadowColor: 'rgba(82,196,26,0.45)'
            },
            data: [{ name: '服务器', value: [...SERVER_LOC, 0] }],
            tooltip: { formatter: '服务器位置' },
          },
        ],
      };

      this.chart.setOption(option, true);
    },

    resizeChart() {
      if (this.chart) this.chart.resize();
    },
  },
};
</script>

<style scoped>
.attack-map-page {
  padding-bottom: 2rem;
}

.map-canvas {
  width: 100%;
  height: 520px;
  border-radius: 0.375rem;
  background: #0d1117;
}

.map-placeholder {
  width: 100%;
  height: 520px;
  background: #0d1117;
  border-radius: 0.375rem;
  color: #6c757d;
}

.gap-2 {
  gap: 0.5rem;
}

.spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.table th {
  font-size: 0.78rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.03em;
}

.badge {
  font-size: 0.75rem;
}
</style>
