"use client";
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { Lock, Mail, Shield } from 'lucide-react';
import Image from 'next/image';

export default function AdminLogin() {
  const router = useRouter();
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      const data = await response.json();

      if (response.ok) {
        router.push('/admin/dashboard');
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err) {
      setError('Connection error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-heritage-cream via-ivory to-sandalwood/10 flex items-center justify-center px-4">
      {/* Background Pattern */}
      <div className="absolute inset-0 opacity-[0.02]">
        <div className="w-full h-full" style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Ctext x='30' y='35' text-anchor='middle' font-size='24' fill='%238B4513'%3Eॐ%3C/text%3E%3C/svg%3E")`,
          backgroundSize: '60px 60px'
        }}></div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative w-full max-w-md"
      >
        <div className="bg-white rounded-lg shadow-2xl overflow-hidden border border-sandalwood/20">
          {/* Header */}
          <div className="bg-gradient-to-r from-sandalwood to-deep-brown px-8 py-6 text-center">
            <Shield className="w-16 h-16 text-ivory mx-auto mb-3" />
            <h1 className="text-2xl font-light text-ivory tracking-wide" style={{ fontFamily: 'Cormorant Garamond, serif' }}>
              Admin Portal
            </h1>
            <p className="text-ivory/80 text-sm mt-1">KuberJi Mandir Management</p>
          </div>

          {/* Form */}
          <div className="p-8">
            <form onSubmit={handleSubmit} className="space-y-6">
              {error && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-red-50 border border-red-200 text-red-600 px-4 py-3 rounded-sm text-sm"
                >
                  {error}
                </motion.div>
              )}

              <div>
                <label className="block text-deep-brown text-sm font-light mb-2">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 text-sandalwood w-5 h-5" />
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="w-full pl-10 pr-4 py-3 border border-sandalwood/30 rounded-sm focus:outline-none focus:border-sandalwood transition-colors"
                    placeholder="admin@kuberjitemple.org"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-deep-brown text-sm font-light mb-2">
                  Password
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-sandalwood w-5 h-5" />
                  <input
                    type="password"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    className="w-full pl-10 pr-4 py-3 border border-sandalwood/30 rounded-sm focus:outline-none focus:border-sandalwood transition-colors"
                    placeholder="Enter your password"
                    required
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-sandalwood hover:bg-deep-brown text-ivory py-3 rounded-sm font-light transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Signing in...' : 'Sign In'}
              </button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-xs text-incense">
                Default: admin@kuberjitemple.org / Admin@123
              </p>
            </div>
          </div>
        </div>

        {/* Back to Website */}
        <div className="mt-6 text-center">
          <button
            onClick={() => router.push('/')}
            className="text-deep-brown hover:text-sandalwood transition-colors text-sm font-light"
          >
            ← Back to Website
          </button>
        </div>
      </motion.div>
    </div>
  );
}
