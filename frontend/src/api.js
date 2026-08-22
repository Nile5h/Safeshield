import axios from 'axios'

// const API_BASE_URL = import.meta.env.VITE_API_URL || "https://safeshield-backend.onrender.com";
const API_BASE_URL = 'http://127.0.0.1:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const analyzeMessage = async (message) => {
  try {
    const response = await api.post('/analyze/message', {
      message: message.trim(),
    })
    return response.data
  } catch (error) {
    throw error.response?.data || { detail: 'Failed to analyze message' }
  }
}

export const analyzeUrl = async (url) => {
  try {
    const response = await api.post('/analyze/url', {
      url: url.trim(),
    })
    return response.data
  } catch (error) {
    throw error.response?.data || { detail: 'Failed to analyze URL' }
  }
}

export const getHealth = async () => {
  try {
    const response = await api.get('/health')
    return response.data
  } catch (error) {
    throw error
  }
}

export const analyzeApk = async (file) => {
  const formData = new FormData()
  formData.append('file', file)

  try {
    const response = await api.post('/analyze/apk', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data
  } catch (error) {
    throw error.response?.data || { detail: 'Failed to analyze APK file' }
  }
}

export const analyzeImage = async (file) => {
  const formData = new FormData()
  formData.append('file', file)

  try {
    const response = await api.post('/analyze/image', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data
  } catch (error) {
    throw error.response?.data || { detail: 'Failed to analyze image' }
  }
}

export const getHistory = async (scanType = null) => {
  try {
    const params = scanType ? { scan_type: scanType } : {}
    const response = await api.get('/history', { params })
    return response.data
  } catch (error) {
    throw error.response?.data || { detail: 'Failed to fetch history' }
  }
}

export const getReportsStats = async () => {
  try {
    const response = await api.get('/reports/stats')
    return response.data
  } catch (error) {
    throw error.response?.data || { detail: 'Failed to fetch report statistics' }
  }
}

export const loginUser = async (username, password) => {
  try {
    const response = await api.post('/login', { username, password })
    return response.data
  } catch (error) {
    throw error.response?.data || { detail: 'Login failed. Please try again.' }
  }
}

export default api
