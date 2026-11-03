/** Static export: the dashboard is plain HTML/JS, hosted on AWS Amplify (or any static host). */
const nextConfig = { output: 'export', reactStrictMode: true, images: { unoptimized: true } };
export default nextConfig;
