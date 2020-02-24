package ucmoudles.systemback.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

/**
 * <p>
 * 本类主要用于 Calendar于字符串之间的转换
 * </p>
 * 
 * @author 9527
 */
public class DateFormater {
	public static String format(String fmt) {
		Calendar cal = new GregorianCalendar();
		int year = cal.get(Calendar.YEAR);
		int month = cal.get(Calendar.MONTH) + 1;
		int day = cal.get(Calendar.DATE);
		int week = cal.get(Calendar.DAY_OF_WEEK);
		int hour = cal.get(Calendar.HOUR);
		int dhour = cal.get(Calendar.HOUR_OF_DAY);
		int minute = cal.get(Calendar.MINUTE);
		int second = cal.get(Calendar.SECOND);
		String[] weekday = { "日", "一", "二", "三", "四", "五", "六" };
		String[] ampm = { "AM", "PM" };

		if (fmt.indexOf("yyyy") != -1) {
			fmt = fmt.replaceAll("yyyy", String.valueOf(year));
		}
		if (fmt.indexOf("yy") != -1) {
			fmt = fmt.replaceAll("yy", String.valueOf(year).substring(2));
		}
		if (fmt.indexOf("MM") != -1) {
			fmt = fmt.replaceAll("MM", month < 10 ? "0" + String.valueOf(month) : String.valueOf(month));
		}
		if (fmt.indexOf("M") != -1) {
			fmt = fmt.replaceAll("M", String.valueOf(month));
		}
		if (fmt.indexOf("dd") != -1) {
			fmt = fmt.replaceAll("dd", day < 10 ? "0" + String.valueOf(day) : String.valueOf(day));
		}
		if (fmt.indexOf("d") != -1) {
			fmt = fmt.replaceAll("d", String.valueOf(day));
		}
		if (fmt.indexOf("w") != -1) {
			fmt = fmt.replaceAll("w", weekday[week - 1]);
		}
		if (fmt.indexOf("HH") != -1) {
			fmt = fmt.replaceAll("HH", dhour < 10 ? "0" + String.valueOf(dhour) : String.valueOf(dhour));
		}
		if (fmt.indexOf("H") != -1) {
			fmt = fmt.replaceAll("HH", String.valueOf(dhour));
		}
		if (fmt.indexOf("hh") != -1) {
			fmt = fmt.replaceAll("hh", String.valueOf(hour) + ampm[cal.get(Calendar.AM_PM)]);
		}
		if (fmt.indexOf("h") != -1) {
			fmt = fmt.replaceAll("h", String.valueOf(hour));
		}
		if (fmt.indexOf("mm") != -1) {
			fmt = fmt.replaceAll("mm", minute < 10 ? "0" + String.valueOf(minute) : String.valueOf(minute));
		}
		if (fmt.indexOf("m") != -1) {
			fmt = fmt.replaceAll("m", String.valueOf(minute));
		}
		if (fmt.indexOf("ss") != -1) {
			fmt = fmt.replaceAll("s", second < 10 ? "0" + String.valueOf(second) : String.valueOf(second));
		}
		if (fmt.indexOf("s") != -1) {
			fmt = fmt.replaceAll("s", String.valueOf(second));
		}
		return fmt;
	}

	/**
	 * 函数表述：本函数返回格式化后的日期(不含时间）
	 * 
	 * @param calendar
	 * @return String 格式化后的日期(不含时间），返回为"yyyy-MM-dd"
	 * 
	 */
	public static String formatDate(Calendar calendar) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd");
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	/**
	 * 函数表述：本函数返回格式化后的日期和时间
	 *
	 * @param calendar
	 * @return String 格式化后的日期和时间,返回为"yyyy-MM-dd HH:mm:ss"
	 *
	 */
	public static String formatDateTime(Calendar calendar) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	/**
	 * 函数描述：将日期格式化成中国式日期
	 *
	 * @param calendar
	 * @return String 格式化后的日期和时间,返回为"yyyy年M月d日"
	 */
	public static String formatDateChinese(Calendar calendar) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy年M月d日");
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	/**
	 * 计算当天截止到23：59：59还剩多少秒
	 *
	 * @return
	 */
	public static long dayRemaindSeconds() {
		long startsec = Calendar.getInstance().getTimeInMillis();

		Calendar endc = Calendar.getInstance();
		endc.set(endc.get(Calendar.YEAR), endc.get(Calendar.MONTH), endc.get(Calendar.DAY_OF_MONTH), 23, 59, 59);

		long endsec = endc.getTimeInMillis();

		return (endsec - startsec) / 1000;
	}

	/**
	 * 按照日期格式格式化日期
	 *
	 * @param calendar
	 * @param format
	 * @return
	 */
	public static String formatDate(Calendar calendar, String format) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat(format);
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	public static Calendar string2Calendar(String dateString) {
		SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date date;
		try {
			date = simpleDateFormat.parse(dateString);
			Calendar c = Calendar.getInstance();
			c.setTime(date);
			return c;
		} catch (ParseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/***
	 * 返回当前月第几周
	 *
	 * @param calendar
	 * @return
	 */
	public static String formatDateToWeek(Calendar calendar) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy年M月第W周");
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	/**
	 * 函数描述：将日期格式化成中国式日期
	 *
	 * @param calendar
	 * @return String 格式化后的日期和时间,返回为"yyyy年M月d日,星期E"
	 */
	public static String formatDateChineseWithWeek(Calendar calendar) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy年M月d日,E");
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	/**
	 * 函数表述：本函数返回格式化后的中国式日期和时间
	 *
	 * @param calendar
	 *            格式化后的日期和时间,返回为"yyyy年M月d日 HH时mm分ss秒,星期E"
	 * @return
	 */
	public static String formatDateTimeChinese(Calendar calendar) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy年M月d日 HH时mm分ss秒,E");
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	public static String formatDateTimeFileName(Calendar calendar) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-M-d-HH:mm:ss");
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	/**
	 * 只返回月份和天
	 *
	 * @param calendar
	 * @return
	 */
	public static String formatDateToMonthDay(Calendar calendar) {
		if (calendar != null) {
			SimpleDateFormat simpleDateFormat = new SimpleDateFormat("M.d");
			return simpleDateFormat.format(calendar.getTime());
		} else {
			return "";
		}
	}

	/**
	 * 获取指定月份指定周日期数据
	 * 
	 * @param curTime
	 * @param week
	 * @return
	 */
	public static Calendar[] getTheWeek(Calendar curTime, int week) {
		Calendar[] cals = new Calendar[7];
		curTime.set(GregorianCalendar.WEEK_OF_MONTH, week);
		curTime.set(GregorianCalendar.DAY_OF_WEEK, GregorianCalendar.MONDAY);
		for (int i = 0; i < cals.length; i++) {
			cals[i] = (Calendar) curTime.clone();
			curTime.add(GregorianCalendar.DAY_OF_MONTH, 1);
		}
		return cals;
	}

	public static int getQuarter(int month) {
		if (month < 3) {
			return 1;
		} else if (month < 6) {
			return 2;
		} else if (month < 9) {
			return 3;
		} else {
			return 4;
		}
	}
	
	/**
	 * 根据日期字符串返回相应的Calendar
	 * 
	 * @param datastr
	 *            日期字符串
	 * @param gs
	 *            日期格式标记，1-"2005-03-12 12:23:32" 2-"2005-03-12"
	 * @return Calendar
	 */
	public static Calendar getCalendarFromString(String dateStr, String format) {
		Date date = new Date();
		SimpleDateFormat dateFormat = new SimpleDateFormat(format);
		try {
			date = dateFormat.parse(dateStr);
			Calendar myCal = Calendar.getInstance();
			myCal.setTime(date);
			return myCal;
		} catch (Exception e) {
			return null;
		}
	}

	public static void main(String[] args) {
		String res = new BCryptPasswordEncoder().encode("root");
		System.out.println(res);
	}


}
