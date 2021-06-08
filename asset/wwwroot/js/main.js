(function($) {
	var Api = $.DohClientApi,
		QTYPE = Api.QTYPE,
		QCLASS = Api.QCLASS;
	var api = new Api({});
	var query = { offset: 0, limit: 100 };
	var loading;

	/* Parse querystring */
	(function(){
		var s = location.search;
		if (s) {
			var arr = s.substr(1).split("&");
			for (var i = 0; i < arr.length; i++) {
				var kv = arr[i].split("=");
				query[kv[0]] = kv[1];
			}

			if (query.offset) {
				query.offset = parseInt(query.offset);
				if (!query.offset)
					query.offset = 0;
				else if (query.offset < 0)
					query.offset = 0;
			}

			if (query.limit) {
				query.limit = parseInt(query.limit);
				if (!query.limit)
					query.offset = 100;
				else if (query.limit < 1)
					query.limit = 100;
			}
		}
	})();

	loading = {
		el: $("#loading"),
		tx: $("#loading-message"),
		show: function (msg) {
			loading.tx.html(msg || "");
			loading.el.css("display", "flex");
		},
		hide: function (msg, delay) {
			if (msg) {
				loading.tx.html(msg || "");
			}
			if (delay) {
				setTimeout(function() {
					loading.el.css("display", "none");
				}, delay);
			}
			else {
				loading.el.css("display", "none");
			}
		}
	};

	function bindTable(r) {
		var html = [];
		if (r.error) {
			html.push('<tr>');
			html.push('  <td class="errmsg" colspan="3">' + (r.msg || "Unknown Error") + '</td>');
			html.push('</tr>');
		}
		else {
			var list = r.data || [];
			var i;
			for (i = 0; i < list.length; i++) {
				var d = list[i] || {};
				html.push('<tr>');
				html.push('  <td>' + (d.key || '') + '</td>');
				html.push('  <td>' + (d.answers || '') + '</td>');
				html.push('  <td><a data-action="remove" data-key="' + (d.key || '') + '" class="remove" title="Remove" href="javascript: void(0);">Remove</a></td>');
				html.push('</tr>');
			}
			if (i == 0) {
				html.push('<tr>');
				html.push('  <td colspan="3">No Data</td>');
				html.push('</tr>');
			}
		}
		$("#tbList > tbody").html(html.join("\n"));
	}

	function bindRangeText(range) {
		if (range) {
			$(".offset-limit").html(range.offset + " - " + (range.offset + range.limit - 1));
		}
		else {
			$(".offset-limit").html("");
		}
	}

	function bindPageBar(range, r) {
		bindRangeText(range);
		if (range && r && !r.error) {
			if (range.offset == 0) {
				$(".prev-page").addClass("disabled");
			}
			else {
				$(".prev-page").removeClass("disabled");
			}
			if (r.data.length < range.limit) {
				$(".next-page").addClass("disabled");
			}
			else {
				$(".next-page").removeClass("disabled");
			}
		}
		else {
			$(".prev-page").addClass("disabled");
			$(".next-page").addClass("disabled");
		}
	}

	function search() {
		loading.show("");
		api.list(query)
		.done(function (r) {
			bindTable(r);
			bindPageBar(query, r);
		})
		.always(function () {
			loading.hide();
		});
	}

	function doListAll() {
		query.offset = 0;
		search();
	}

	function doGet() {
		var d = {
			"type":  $("#txType").val(),
			"class": $("#txClass").val(),
			"name":  $("#txDomain").val()
		};
		if (!d.name) {
			alert("Please input domain");
			$("#txDomain").focus();
			return;
		}
		loading.show("");
		api.get(d)
		.done(function (r) {
			if (!r.error)
				r.data = [r.data];
			bindTable(r);
			bindPageBar(null, r);
		})
		.always(function () {
			loading.hide();
		});
	}

	function doPut() {
		var d = {
			"type":  $("#txType2").val(),
			"ip":    $("#txIP").val(),
			"name":  $("#txDomain2").val(),
			"ttl":   $("#txTTL").val()
		};
		if (!d.ip) {
			alert("Please input IP");
			$("#txIP").focus();
			return;
		}
		if (!d.name) {
			alert("Please input domain");
			$("#txDomain2").focus();
			return;
		}
		loading.show("");
		api.put(d)
		.always(function (r, textStatus, errorThrown) {
			if (textStatus === "success") {
				if (!r.error) {
					if (confirm("Success! Refresh the list?")) {
						search();
					}
				}
				else {
					loading.hide();
					alert(r.msg || "Unknown Error");
				}
			}
			else {
				loading.hide();
				alert(errorThrown);
			}
		});
	}

	function doRefresh() {
		search();
	}

	function doRemove(d) {
		if (confirm("Sure to remove?")) {
			loading.show("");
			api.delete({
				key: d.key
			})
			.always(function (r, textStatus, errorThrown) {
				if (textStatus === "success") {
					if (!r.error) {
						search();
					}
					else {
						loading.hide();
						alert(r.msg || "Unknown Error");
					}
				}
				else {
					loading.hide();
					alert(errorThrown);
				}
			});
		}
	}

	function doPrevPage() {
		if (!$(a).hasClass("disabled") && query.offset > 0) {
			query.offset -= query.limit;
			if (query.offset < 0)
				query.offset = 0;
			search();
		}
	}

	function doNextPage() {
		if (!$(a).hasClass("disabled")) {
			query.offset += query.limit;
			search();
		}
	}

	function doAction(e) {
		var a = e.currentTarget;
		var d = $(a).data();
		console.log(e,d);
		switch (d.action) {
			case "refresh":
				doRefresh();
				break;
			case "remove":
				doRemove(d);
				break;
			case "prev-page":
				doPrevPage();
				break;
			case "next-page":
				doNextPage();
				break;
		}
	}

	$(function() {
		search();
		$("#btnListAll").click(doListAll);
		$("#btnGet").click(doGet);
		$("#btnPut").click(doPut);
		$("#tbList").on("click", "a", doAction);
	});
})(jQuery);
