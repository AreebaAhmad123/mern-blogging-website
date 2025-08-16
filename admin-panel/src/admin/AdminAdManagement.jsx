import React, { useState, useContext, useEffect } from "react";
import { uploadImage } from "../common/cloudinary";
import Loader from "../components/loader.component";
import { UserContext } from "../App";
import axios from "axios";
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";

const COLORS = ["#0088FE", "#FFBB28", "#00C49F", "#FF8042"];

const AdminAdManagement = () => {
  const { userAuth } = useContext(UserContext);
  const [banners, setBanners] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [editingLinkId, setEditingLinkId] = useState(null);
  const [editingLinkValue, setEditingLinkValue] = useState("");
  const [actionLoading, setActionLoading] = useState("");
  const [previewUrl, setPreviewUrl] = useState(null);
  const [selectedBannerIds, setSelectedBannerIds] = useState([]);

  const urlRegex = /^https?:\/\/.+/;
  const isAdmin = userAuth?.admin === true || userAuth?.super_admin === true;

  // Fetch all banners
  const fetchBanners = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await axios.get(`${import.meta.env.VITE_SERVER_DOMAIN}/api/admin/ad-banners`, {
        headers: { Authorization: `Bearer ${userAuth.access_token}` },
      });
      setBanners(res.data.banners || []);
    } catch (err) {
      setBanners([]);
      setError("Failed to fetch banners.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBanners();
    // eslint-disable-next-line
  }, []);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    setSelectedFile(file);
    setError("");
    setSuccess("");
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => setPreviewUrl(reader.result);
      reader.readAsDataURL(file);
    } else {
      setPreviewUrl(null);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError("Please select an image file.");
      return;
    }
    setUploading(true);
    setError("");
    setSuccess("");
    try {
      const imageUrl = await uploadImage(selectedFile, userAuth.access_token);
      // Save banner to backend
      const res = await axios.post(
        `${import.meta.env.VITE_SERVER_DOMAIN}/api/admin/ad-banner`,
        { imageUrl },
        { headers: { Authorization: `Bearer ${userAuth.access_token}` } }
      );
      setSuccess("Banner uploaded and saved successfully!");
      setSelectedFile(null);
      setPreviewUrl(null);
      fetchBanners();
    } catch (err) {
      setError(err.response?.data?.error || err.message || "Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  const handleSetVisible = async (id) => {
    setActionLoading(id + "-visible");
    setError("");
    setSuccess("");
    try {
      await axios.put(
        `${import.meta.env.VITE_SERVER_DOMAIN}/api/admin/ad-banner/${id}`,
        { visible: true },
        { headers: { Authorization: `Bearer ${userAuth.access_token}` } }
      );
      setSuccess("Banner set as visible.");
      fetchBanners();
    } catch (err) {
      setError(err.response?.data?.error || err.message || "Failed to set visible.");
    } finally {
      setActionLoading("");
    }
  };

  const handleHide = async (id) => {
    setActionLoading(id + "-hide");
    setError("");
    setSuccess("");
    try {
      await axios.patch(
        `${import.meta.env.VITE_SERVER_DOMAIN}/api/admin/ad-banner/${id}/hide`,
        {},
        { headers: { Authorization: `Bearer ${userAuth.access_token}` } }
      );
      setSuccess("Banner hidden.");
      fetchBanners();
    } catch (err) {
      setError(err.response?.data?.error || err.message || "Failed to hide banner.");
    } finally {
      setActionLoading("");
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Are you sure you want to delete this banner? This action cannot be undone.")) return;
    setActionLoading(id + "-delete");
    setError("");
    setSuccess("");
    try {
      await axios.delete(
        `${import.meta.env.VITE_SERVER_DOMAIN}/api/admin/ad-banner/${id}`,
        { headers: { Authorization: `Bearer ${userAuth.access_token}` } }
      );
      setSuccess("Banner deleted.");
      fetchBanners();
    } catch (err) {
      setError(err.response?.data?.error || err.message || "Failed to delete banner.");
    } finally {
      setActionLoading("");
    }
  };

  const handleEditLink = (id, currentLink) => {
    setEditingLinkId(id);
    setEditingLinkValue(currentLink || "");
    setError("");
    setSuccess("");
  };

  const handleSaveLink = async (id) => {
    setActionLoading(id + "-link");
    setError("");
    setSuccess("");
    if (editingLinkValue && !urlRegex.test(editingLinkValue)) {
      setError("Invalid link URL. Must start with http:// or https://");
      setActionLoading("");
      return;
    }
    try {
      await axios.put(
        `${import.meta.env.VITE_SERVER_DOMAIN}/api/admin/ad-banner/${id}`,
        { link: editingLinkValue },
        { headers: { Authorization: `Bearer ${userAuth.access_token}` } }
      );
      setSuccess("Banner link updated.");
      setEditingLinkId(null);
      fetchBanners();
    } catch (err) {
      setError(err.response?.data?.error || err.message || "Failed to update link.");
    } finally {
      setActionLoading("");
    }
  };

  const handleSelectBanner = (id) => {
    setSelectedBannerIds((prev) =>
      prev.includes(id) ? prev.filter((b) => b !== id) : [...prev, id]
    );
  };
  const handleSelectAll = () => {
    if (selectedBannerIds.length === banners.length) {
      setSelectedBannerIds([]);
    } else {
      setSelectedBannerIds(banners.map((b) => b._id));
    }
  };
  const handleBulkDelete = async () => {
    if (!window.confirm('Are you sure you want to delete the selected banners? This action cannot be undone.')) return;
    setActionLoading('bulk-delete');
    setError("");
    setSuccess("");
    try {
      await Promise.all(selectedBannerIds.map(id => axios.delete(
        `${import.meta.env.VITE_SERVER_DOMAIN}/api/admin/ad-banner/${id}`,
        { headers: { Authorization: `Bearer ${userAuth.access_token}` } }
      )));
      setSuccess('Selected banners deleted.');
      setSelectedBannerIds([]);
      fetchBanners();
    } catch (err) {
      setError('Bulk delete failed. Some banners may not have been deleted.');
    } finally {
      setActionLoading("");
    }
  };
  const handleBulkHide = async () => {
    setActionLoading('bulk-hide');
    setError("");
    setSuccess("");
    try {
      await Promise.all(selectedBannerIds.map(id => axios.patch(
        `${import.meta.env.VITE_SERVER_DOMAIN}/api/admin/ad-banner/${id}/hide`,
        {},
        { headers: { Authorization: `Bearer ${userAuth.access_token}` } }
      )));
      setSuccess('Selected banners hidden.');
      setSelectedBannerIds([]);
      fetchBanners();
    } catch (err) {
      setError('Bulk hide failed. Some banners may not have been hidden.');
    } finally {
      setActionLoading("");
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto p-2 sm:p-4 bg-white dark:bg-black rounded shadow mt-4 sm:mt-6">
      <div className="text-xs sm:text-sm md:text-base lg:text-lg xl:text-xl font-bold mb-2 sm:mb-4 text-gray-900 dark:text-white">Ad Management</div>
      <div className="mb-6">
        <label className="block font-medium mb-2 text-gray-800 dark:text-white">Upload New Banner Image:</label>
        {previewUrl && (
          <div className="mb-2 bg-white dark:bg-black p-2 sm:p-4 rounded flex justify-center">
            <img src={previewUrl} alt="Preview" className="w-full max-w-xs sm:w-64 h-auto rounded shadow border bg-white dark:bg-black" />
          </div>
        )}
        <div className="flex flex-col sm:flex-row gap-2 sm:gap-4 items-stretch sm:items-center">
          <input type="file" accept="image/*" onChange={handleFileChange} disabled={uploading} className="text-gray-900 dark:text-white bg-white dark:bg-black w-full sm:w-auto" />
          <button
            className="px-4 py-2 bg-blue-600 dark:bg-black text-white rounded hover:bg-blue-700 dark:hover:bg-gray-900 disabled:opacity-50 border dark:border-white w-full sm:w-auto"
            onClick={handleUpload}
            disabled={uploading || !selectedFile}
          >
            {uploading ? <Loader size="small" /> : "Upload & Save"}
          </button>
        </div>
      </div>
      {error && <div className="mt-2 text-red dark:text-red">{error}</div>}
      {success && <div className="mt-2 text-green-600 dark:text-green-400">{success}</div>}
      <div className="mt-8">
        <div className="text-xs sm:text-sm md:text-base lg:text-lg font-semibold mb-1 sm:mb-2 text-gray-900 dark:text-white">All Ad Banners</div>
        {selectedBannerIds.length > 0 && (
          <div className="mb-2 flex flex-col sm:flex-row gap-2">
            <button
              className="px-3 py-1 bg-red dark:bg-black text-white rounded disabled:opacity-50 border dark:border-white w-full sm:w-auto"
              onClick={handleBulkDelete}
              disabled={actionLoading === 'bulk-delete'}
            >
              Delete Selected
            </button>
            <button
              className="px-3 py-1 bg-gray-700 dark:bg-black text-white rounded disabled:opacity-50 border dark:border-white w-full sm:w-auto"
              onClick={handleBulkHide}
              disabled={actionLoading === 'bulk-hide'}
            >
              Hide Selected
            </button>
            <span className="text-sm text-gray-700 dark:text-white self-center">{selectedBannerIds.length} selected</span>
          </div>
        )}
        {loading ? (
          <Loader size="medium" />
        ) : banners.length === 0 ? (
          <div className="text-gray-600 dark:text-gray-300 italic mb-2">No banners uploaded yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full border text-xs sm:text-sm">
              <thead>
                <tr className="bg-gray-100 dark:bg-black">
                  <th className="p-1 sm:p-2 border text-gray-900 dark:text-white bg-gray-100 dark:bg-black">
                    <input
                      type="checkbox"
                      checked={selectedBannerIds.length === banners.length && banners.length > 0}
                      onChange={handleSelectAll}
                    />
                  </th>
                  <th className="p-1 sm:p-2 border text-gray-900 dark:text-white bg-gray-100 dark:bg-black">Image</th>
                  <th className="p-1 sm:p-2 border text-gray-900 dark:text-white bg-gray-100 dark:bg-black">Link</th>
                  <th className="p-1 sm:p-2 border text-gray-900 dark:text-white bg-gray-100 dark:bg-black">Visible</th>
                  <th className="p-1 sm:p-2 border text-gray-900 dark:text-white bg-gray-100 dark:bg-black hidden xs:table-cell">Views</th>
                  <th className="p-1 sm:p-2 border text-gray-900 dark:text-white bg-gray-100 dark:bg-black hidden xs:table-cell">Clicks</th>
                  <th className="p-1 sm:p-2 border text-gray-900 dark:text-white bg-gray-100 dark:bg-black">Actions</th>
                </tr>
              </thead>
              <tbody>
                {banners.map((banner) => (
                  <tr key={banner._id} className={banner.visible ? "bg-green-50 dark:bg-black" : "dark:bg-black"}>
                    <td className="p-1 sm:p-2 border text-center dark:text-white dark:bg-black">
                      <input
                        type="checkbox"
                        checked={selectedBannerIds.includes(banner._id)}
                        onChange={() => handleSelectBanner(banner._id)}
                      />
                    </td>
                    <td className="p-1 sm:p-2 border dark:text-white dark:bg-black">
                      <img src={banner.imageUrl} alt="Ad Banner" className="w-20 sm:w-32 max-h-20 sm:max-h-24 object-contain rounded border bg-white dark:bg-black mx-auto" />
                    </td>
                    <td className="p-1 sm:p-2 border dark:text-white dark:bg-black max-w-[120px] sm:max-w-xs break-words">
                      {editingLinkId === banner._id ? (
                        <div className="flex flex-col sm:flex-row gap-2 items-stretch sm:items-center">
                          <input
                            type="text"
                            value={editingLinkValue}
                            onChange={e => setEditingLinkValue(e.target.value)}
                            className="border px-2 py-1 rounded w-full sm:w-40 text-gray-900 dark:text-white bg-white dark:bg-black"
                          />
                          <button
                            className="px-2 py-1 bg-blue-500 dark:bg-black text-white rounded border dark:border-white w-full sm:w-auto"
                            onClick={() => handleSaveLink(banner._id)}
                            disabled={actionLoading === banner._id + "-link"}
                          >Save</button>
                          <button
                            className="px-2 py-1 bg-gray-300 dark:bg-black text-gray-900 dark:text-white rounded border dark:border-white w-full sm:w-auto"
                            onClick={() => setEditingLinkId(null)}
                          >Cancel</button>
                        </div>
                      ) : (
                        <div className="flex flex-col sm:flex-row gap-2 items-stretch sm:items-center">
                          <span className="text-gray-800 dark:text-white break-all" title={banner.link || ''}>
                            {banner.link
                              ? banner.link.length > 20
                                ? banner.link.slice(0, 20) + '...'
                                : banner.link
                              : <span className="text-gray-400 dark:text-gray-500">(none)</span>}
                          </span>
                          <button
                            className="px-2 py-1 bg-yellow-400 dark:bg-black text-gray-900 dark:text-white rounded border dark:border-white w-full sm:w-auto"
                            onClick={() => handleEditLink(banner._id, banner.link)}
                          >Edit</button>
                        </div>
                      )}
                    </td>
                    <td className="p-1 sm:p-2 border text-center font-bold dark:text-white dark:bg-black">
                      {banner.visible ? <span className="text-green-700 dark:text-white">Yes</span> : <span className="text-gray-500 dark:text-white">No</span>}
                    </td>
                    <td className="p-1 sm:p-2 border text-center text-gray-800 dark:text-white dark:bg-black hidden xs:table-cell">{banner.views}</td>
                    <td className="p-1 sm:p-2 border text-center text-gray-800 dark:text-white dark:bg-black hidden xs:table-cell">{banner.clicks}</td>
                    <td className="p-1 sm:p-2 border dark:text-white dark:bg-black">
                      <div className="flex flex-col sm:flex-row gap-2">
                        {banner.visible ? null : (
                          <button
                            className="px-2 py-1 bg-green-500 dark:bg-black text-white rounded border dark:border-white w-full sm:w-auto"
                            onClick={() => handleSetVisible(banner._id)}
                            disabled={actionLoading === banner._id + "-visible"}
                          >Set Visible</button>
                        )}
                        <button
                          className="px-2 py-1 bg-gray-400 dark:bg-black text-white rounded border dark:border-white w-full sm:w-auto"
                          onClick={() => handleHide(banner._id)}
                          disabled={actionLoading === banner._id + "-hide" || !banner.visible}
                        >Hide</button>
                        <button
                          className="px-2 py-1 bg-red dark:bg-black text-white rounded border dark:border-white w-full sm:w-auto"
                          onClick={() => handleDelete(banner._id)}
                          disabled={actionLoading === banner._id + "-delete"}
                        >Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {/* Analytics Pie Chart for visible banner */}
      <div className="mt-8">
        <div className="text-xs sm:text-sm md:text-base lg:text-lg font-semibold mb-1 sm:mb-2 text-gray-900 dark:text-white">Visible Banner Analytics</div>
        {banners.length > 0 && banners.find(b => b.visible) ? (
          <div className="w-full h-48 sm:h-64 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={[
                    { name: "Views", value: banners.find(b => b.visible).views },
                    { name: "Clicks", value: banners.find(b => b.visible).clicks },
                  ]}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                  fill="#8884d8"
                  label
                >
                  <Cell key="cell-0" fill={COLORS[0]} />
                  <Cell key="cell-1" fill={COLORS[1]} />
                </Pie>
                <Tooltip contentStyle={{ color: '#fff', background: '#111' }} wrapperStyle={{ color: '#fff' }}/>
                <Legend wrapperStyle={{ color: '#fff' }}/>
              </PieChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="text-gray-600 dark:text-gray-300 italic">No visible banner for analytics.</div>
        )}
      </div>
    </div>
  );
};

export default AdminAdManagement; 