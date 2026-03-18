import Vue from 'vue'

const DEFAULT_DURATION = 5000
const MAX_TOASTS = 5

const state = Vue.observable({
  items: [],
  nextId: 1
})

function enqueue(level, message, options = {}) {
  const text = String(message || '').trim()
  if (!text) {
    return null
  }

  const id = state.nextId++
  const duration = typeof options.duration === 'number' && options.duration >= 0
    ? options.duration
    : DEFAULT_DURATION

  state.items.push({
    id,
    level,
    message: text
  })

  if (state.items.length > MAX_TOASTS) {
    state.items.splice(0, state.items.length - MAX_TOASTS)
  }

  if (duration > 0) {
    window.setTimeout(() => {
      remove(id)
    }, duration)
  }

  return id
}

function remove(id) {
  const index = state.items.findIndex((item) => item.id === id)
  if (index !== -1) {
    state.items.splice(index, 1)
  }
}

const toast = {
  state,
  show(message, level = 'info', options) {
    return enqueue(level, message, options)
  },
  success(message, options) {
    return enqueue('success', message, options)
  },
  info(message, options) {
    return enqueue('info', message, options)
  },
  warning(message, options) {
    return enqueue('warning', message, options)
  },
  error(message, options) {
    return enqueue('error', message, options)
  },
  remove
}

export default toast
