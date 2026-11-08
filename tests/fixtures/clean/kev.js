// Threat-intel vocabulary that is not a ransom note (CISA KEV columns).
const columns = ['cve_id', 'kev_known', 'ransomware_use', 'ransomware_name', 'updated_at'];

function toRow(kev) {
  return {
    ransomware_use: kev.knownRansomwareCampaignUse || '',
    ransomware_name: kev.ransomwareName || '',
  };
}

module.exports = { columns, toRow };
