DROP TABLE IF EXISTS `tds_bypass`;
CREATE TABLE `tds_bypass`
(
    `dest_url` varchar(255) primary key,
    `src_url`  varchar(255) NOT NULL
);
