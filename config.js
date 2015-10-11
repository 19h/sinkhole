module.exports = {
	/* record age in lookup map */
	eTTL: 30 * 1000,
	/* ban time */
	sinkholeTTL: 3600 * 4 * 1000,
	/* max age of consensus until re-download */
	consensusMaxAge: 3600 * 3 * 1000
};
