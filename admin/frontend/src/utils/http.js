export function getApiErrorMessage(error, fallback = '请求失败') {
  const responseMessage = error &&
    error.response &&
    error.response.data &&
    typeof error.response.data.message === 'string'
    ? error.response.data.message.trim()
    : ''

  if (responseMessage) {
    return responseMessage
  }

  if (!error || !error.response) {
    const rawMessage = error && typeof error.message === 'string'
      ? error.message.trim()
      : ''
    if (!rawMessage || rawMessage === 'Network Error') {
      return fallback
    }
    return rawMessage
  }

  return fallback
}

export function shouldHandleLocally(error) {
  return !(error && error.__globalToastShown)
}
