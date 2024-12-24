using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace JenkinsCA
{
    /// <summary>Indicates the type of objects the DirectoryObjectPickerDialog searches for.</summary>
    [Flags]
    public enum ObjectTypes
    {
        /// <summary>No object types.</summary>
        None = 0x0,

        /// <summary>Includes user objects.</summary>
        Users = 0x0001,

        /// <summary>Includes security groups with universal scope.</summary>
        /// <remarks>
        /// <para>In an up-level scope, this includes distribution and security groups, with universal, global and domain local scope.</para>
        /// <para>In a down-level scope, this includes local and global groups.</para>
        /// </remarks>
        Groups = 0x0002,

        /// <summary>Includes computer objects.</summary>
        Computers = 0x0004,

        /// <summary>Includes contact objects.</summary>
        Contacts = 0x0008,

        /// <summary>Includes built-in group objects.</summary>
        /// <summary>
        /// <para>In an up-level scope, this includes group objects with the built-in groupType flags.</para>
        /// <para>In a down-level scope, not setting this object type excludes local built-in groups.</para>
        /// </summary>
        BuiltInGroups = 0x0010,

        /// <summary>Includes all well-known security principals.</summary>
        /// <remarks>
        /// <para>In an up-level scope, this includes the contents of the Well Known Security Principals container.</para>
        /// <para>In a down-level scope, this includes all well-known SIDs.</para>
        /// </remarks>
        WellKnownPrincipals = 0x0020,

        /// <summary>Includes all service accounts and group managed service accounts.</summary>
        ServiceAccounts = 0x0040,

        /// <summary>All object types.</summary>
        All = 0x007F
    }

    /// <summary>Indicates the scope the DirectoryObjectPickerDialog searches for objects.</summary>
	[Flags]
    public enum Locations
    {
        /// <summary>No locations.</summary>
        None = 0x0,

        /// <summary>The target computer (down-level).</summary>
        LocalComputer = 0x0001,

        /// <summary>A domain to which the target computer is joined (down-level and up-level).</summary>
        JoinedDomain = 0x0002,

        /// <summary>All Windows 2000 domains in the enterprise to which the target computer belongs (up-level).</summary>
        EnterpriseDomain = 0x0004,

        /// <summary>A scope containing objects from all domains in the enterprise (up-level).</summary>
        GlobalCatalog = 0x0008,

        /// <summary>
        /// All domains external to the enterprise, but trusted by the domain to which the target computer is joined (down-level and up-level).
        /// </summary>
        ExternalDomain = 0x0010,

        /// <summary>The workgroup to which the target computer is joined (down-level).</summary>
        /// <remarks>
        /// <para>
        /// Applies only if the target computer is not joined to a domain. The only type of object that can be selected from a workgroup is
        /// a computer.
        /// </para>
        /// </remarks>
        Workgroup = 0x0020,

        /// <summary>Enables the user to enter a scope (down-level and up-level).</summary>
        /// <remarks>
        /// <para>If not specified, the dialog box restricts the user to the scopes in the locations drop-down list.</para>
        /// </remarks>
        UserEntered = 0x0040,

        /// <summary>All locations.</summary>
        All = 0x007F
    }

    /// <summary>
	/// Indicates the ADsPaths provider type of the DirectoryObjectPickerDialog. This provider affects the contents of the ADPath returned
	/// </summary>
	[Flags]
    public enum ADsPathsProviders
    {
        /// <summary>Default provider.</summary>
        Default = 0,

        /// <summary>
        /// The ADsPaths are converted to use the WinNT provider.
        ///
        /// The ADsPath string for the ADSI WinNT provider can be one of the following forms:
        /// <code>
        ///WinNT:
        ///WinNT://&lt;domain name&gt;
        ///WinNT://&lt;domain name&gt;/&lt;server&gt;
        ///WinNT://&lt;domain name&gt;/&lt;path&gt;
        ///WinNT://&lt;domain name&gt;/&lt;object name&gt;
        ///WinNT://&lt;domain name&gt;/&lt;object name&gt;,&lt;object class&gt;
        ///WinNT://&lt;server&gt;
        ///WinNT://&lt;server&gt;/&lt;object name&gt;
        ///WinNT://&lt;server&gt;/&lt;object name&gt;,&lt;object class&gt;
        /// </code>
        /// The domain name can be either a NETBIOS name or a DNS name. The server is the name of a specific server within the domain. The
        /// path is the path of on object, such as "printserver1/printer2". The object name is the name of a specific object. The object
        /// class is the class name of the named object. One example of this usage would be "WinNT://MyServer/JeffSmith,user". Specifying a
        /// class name can improve the performance of the bind operation.
        /// </summary>
        WinNT = 0x00000002,

        /// <summary>
        /// The ADsPaths are converted to use the LDAP provider.
        /// <para>The Microsoft LDAP provider ADsPath requires the following format.</para>
        /// <para>LDAP://HostName[:PortNumber][/DistinguishedName]</para>
        /// <para>Further info, see <a href="http://msdn.microsoft.com/en-us/library/aa746384(v=VS.85).aspx">http://msdn.microsoft.com/en-us/library/aa746384(v=VS.85).aspx</a>.</para>
        /// </summary>
        LDAP = 0x00000004,

        /// <summary>The ADsPaths for objects selected from this scope are converted to use the GC provider.</summary>
        GC = 0x00000008,

        /// <summary>
        /// The ADsPaths having an objectSid attribute are converted to the form
        /// <code>
        ///LDAP://&lt;SID=x&gt;
        /// </code>
        /// where x represents the hexadecimal digits of the objectSid attribute value.
        /// </summary>
        SIDPath = 0x00000010,

        /// <summary>
        /// The ADsPaths for down-level, well-known SID objects are an empty string unless this flag is specified (For example;
        /// DSOP_DOWNLEVEL_FILTER_INTERACTIVE). If this flag is specified, the paths have the form:
        /// <para><c>WinNT://NT AUTHORITY/Interactive</c> or <c>WinNT://Creator owner</c>.</para>
        /// </summary>
        DownlevelBuiltinPath = 0x00000020,

        /// <summary>Use DownlevelBuiltinPath instead.</summary>
        [Obsolete("Use DownlevelBuiltinPath instead.")]
        DownlevelBuildinPath = 0x00000020
    }

    /// <summary>Filter flags to use for an up-level scope, regardless of whether it is a mixed or native mode domain.</summary>
	internal enum DSOP_FILTER_FLAGS_FLAGS : uint
    {
        DSOP_FILTER_BUILTIN_GROUPS = 0x00000004,
        DSOP_FILTER_COMPUTERS = 0x00000800,
        DSOP_FILTER_CONTACTS = 0x00000400,
        DSOP_FILTER_DOMAIN_LOCAL_GROUPS_DL = 0x00000100,
        DSOP_FILTER_DOMAIN_LOCAL_GROUPS_SE = 0x00000200,
        DSOP_FILTER_GLOBAL_GROUPS_DL = 0x00000040,
        DSOP_FILTER_GLOBAL_GROUPS_SE = 0x00000080,
        DSOP_FILTER_INCLUDE_ADVANCED_VIEW = 0x00000001,
        DSOP_FILTER_SERVICE_ACCOUNTS = 0x00001000,
        DSOP_FILTER_UNIVERSAL_GROUPS_DL = 0x00000010,
        DSOP_FILTER_UNIVERSAL_GROUPS_SE = 0x00000020,
        DSOP_FILTER_USERS = 0x00000002,
        DSOP_FILTER_WELL_KNOWN_PRINCIPALS = 0x00000008,
    }

    /// <summary>Flags that determine the object picker options.</summary>
	internal enum DSOP_INIT_INFO_FLAGS : uint
    {
        DSOP_FLAG_MULTISELECT = 0x00000001,
        DSOP_FLAG_SKIP_TARGET_COMPUTER_DC_CHECK = 0x00000002,
    }

    /// <summary>
	/// Flags that indicate the format used to return ADsPath for objects selected from this scope. The flScope member can also indicate the
	/// initial scope displayed in the Look in drop-down list.
	/// </summary>
	internal enum DSOP_SCOPE_INIT_INFO_FLAGS : uint
    {
        DSOP_SCOPE_FLAG_DEFAULT_FILTER_COMPUTERS = 0x00000100,
        DSOP_SCOPE_FLAG_DEFAULT_FILTER_CONTACTS = 0x00000200,
        DSOP_SCOPE_FLAG_DEFAULT_FILTER_GROUPS = 0x00000080,
        DSOP_SCOPE_FLAG_DEFAULT_FILTER_PASSWORDSETTINGS_OBJECTS = 0x00000800,
        DSOP_SCOPE_FLAG_DEFAULT_FILTER_SERVICE_ACCOUNTS = 0x00000400,
        DSOP_SCOPE_FLAG_DEFAULT_FILTER_USERS = 0x00000040,
        DSOP_SCOPE_FLAG_STARTING_SCOPE = 0x00000001,
        DSOP_SCOPE_FLAG_WANT_DOWNLEVEL_BUILTIN_PATH = 0x00000020,
        DSOP_SCOPE_FLAG_WANT_PROVIDER_GC = 0x00000008,
        DSOP_SCOPE_FLAG_WANT_PROVIDER_LDAP = 0x00000004,
        DSOP_SCOPE_FLAG_WANT_PROVIDER_WINNT = 0x00000002,
        DSOP_SCOPE_FLAG_WANT_SID_PATH = 0x00000010,
    }

    /// <summary>Contains the filter flags to use for down-level scopes</summary>
    internal enum DSOP_DOWNLEVEL_FLAGS : uint
    {
        DSOP_DOWNLEVEL_FILTER_ALL_WELLKNOWN_SIDS = 0x80020000,
        DSOP_DOWNLEVEL_FILTER_ANONYMOUS = 0x80000040,
        DSOP_DOWNLEVEL_FILTER_AUTHENTICATED_USER = 0x80000020,
        DSOP_DOWNLEVEL_FILTER_BATCH = 0x80000080,
        DSOP_DOWNLEVEL_FILTER_COMPUTERS = 0x80000008,
        DSOP_DOWNLEVEL_FILTER_CREATOR_GROUP = 0x80000200,
        DSOP_DOWNLEVEL_FILTER_CREATOR_OWNER = 0x80000100,
        DSOP_DOWNLEVEL_FILTER_DIALUP = 0x80000400,
        DSOP_DOWNLEVEL_FILTER_EXCLUDE_BUILTIN_GROUPS = 0x80008000,
        DSOP_DOWNLEVEL_FILTER_GLOBAL_GROUPS = 0x80000004,
        DSOP_DOWNLEVEL_FILTER_IIS_APP_POOL = 0x84000000,
        DSOP_DOWNLEVEL_FILTER_INTERACTIVE = 0x80000800,
        DSOP_DOWNLEVEL_FILTER_INTERNET_USER = 0x80200000,
        DSOP_DOWNLEVEL_FILTER_LOCAL_GROUPS = 0x80000002,
        DSOP_DOWNLEVEL_FILTER_LOCAL_LOGON = 0x81000000,
        DSOP_DOWNLEVEL_FILTER_LOCAL_SERVICE = 0x80040000,
        DSOP_DOWNLEVEL_FILTER_NETWORK = 0x80001000,
        DSOP_DOWNLEVEL_FILTER_NETWORK_SERVICE = 0x80080000,
        DSOP_DOWNLEVEL_FILTER_OWNER_RIGHTS = 0x80400000,
        DSOP_DOWNLEVEL_FILTER_REMOTE_LOGON = 0x80100000,
        DSOP_DOWNLEVEL_FILTER_SERVICE = 0x80002000,
        DSOP_DOWNLEVEL_FILTER_SERVICES = 0x80800000,
        DSOP_DOWNLEVEL_FILTER_SYSTEM = 0x80004000,
        DSOP_DOWNLEVEL_FILTER_TERMINAL_SERVER = 0x80010000,
        DSOP_DOWNLEVEL_FILTER_THIS_ORG_CERT = 0x82000000,
        DSOP_DOWNLEVEL_FILTER_USERS = 0x80000001,
        DSOP_DOWNLEVEL_FILTER_WORLD = 0x80000010,
    }

    /// <summary>
    /// Flags that indicate the scope types described by this structure. You can combine multiple scope types if all specified scopes use
    /// the same settings.
    /// </summary>
    [Flags]
    internal enum DSOP_SCOPE_TYPE_FLAGS : uint
    {
        DSOP_SCOPE_TYPE_DOWNLEVEL_JOINED_DOMAIN = 0x00000004,
        DSOP_SCOPE_TYPE_ENTERPRISE_DOMAIN = 0x00000008,
        DSOP_SCOPE_TYPE_EXTERNAL_DOWNLEVEL_DOMAIN = 0x00000040,
        DSOP_SCOPE_TYPE_EXTERNAL_UPLEVEL_DOMAIN = 0x00000020,
        DSOP_SCOPE_TYPE_GLOBAL_CATALOG = 0x00000010,
        DSOP_SCOPE_TYPE_TARGET_COMPUTER = 0x00000001,
        DSOP_SCOPE_TYPE_UPLEVEL_JOINED_DOMAIN = 0x00000002,
        DSOP_SCOPE_TYPE_USER_ENTERED_DOWNLEVEL_SCOPE = 0x00000200,
        DSOP_SCOPE_TYPE_USER_ENTERED_UPLEVEL_SCOPE = 0x00000100,
        DSOP_SCOPE_TYPE_WORKGROUP = 0x00000080,
    }

    /// <summary>Details of a directory object selected in the DirectoryObjectPickerDialog.</summary>
	public class DirectoryObject
    {
        /// <summary>Initializes a new instance of the <see cref="DirectoryObject"/> class.</summary>
        /// <param name="name">The directory object's relative distinguished name (RDN).</param>
        /// <param name="path">The Active Directory path for this directory object.</param>
        /// <param name="schemaClass">The name of the schema class for this directory object (objectClass attribute).</param>
        /// <param name="upn">The objects user principal name (userPrincipalName attribute).</param>
        /// <param name="fetchedAttributes">The attributes retrieved by the object picker as it makes the selection.</param>
        public DirectoryObject(string name, string path, string schemaClass, string upn, object[] fetchedAttributes)
        {
            this.Name = name;
            this.Path = path;
            this.SchemaClassName = schemaClass;
            this.Upn = upn;
            this.FetchedAttributes = fetchedAttributes;
        }

        /// <summary>Gets attributes retrieved by the object picker as it makes the selection.</summary>
        public object[] FetchedAttributes { get; private set; }

        /// <summary>Gets the directory object's relative distinguished name (RDN).</summary>
        public string Name { get; private set; }

        /// <summary>Gets the Active Directory path for this directory object.</summary>
        /// <remarks>
        /// <para>
        /// The format of this string depends on the options specified in the DirectoryObjectPickerDialog from which this object was selected.
        /// </para>
        /// </remarks>
        public string Path { get; private set; }

        /// <summary>Gets the name of the schema class for this directory object (objectClass attribute).</summary>
        public string SchemaClassName { get; private set; }

        /// <summary>Gets the objects user principal name (userPrincipalName attribute).</summary>
        /// <remarks>
        /// <para>If the object does not have a userPrincipalName value, this property is an empty string.</para>
        /// </remarks>
        public string Upn { get; private set; }
    }

    // based on the packLPArray class. original from mailing list post by Beat Bucheli. or maybe from
    // http://blogs.technolog.nl/eprogrammer/archive/2005/11/24/402.aspx or maybe from somewhere else..
    /// <summary>A packed array of strings.</summary>
    /// <seealso cref="System.IDisposable"/>
    public sealed class UnmanagedArrayOfStrings : IDisposable
    {
        private readonly IntPtr[] _unmanagedStrings;

        /// <summary>Initializes a new instance of the <see cref="UnmanagedArrayOfStrings"/> class.</summary>
        /// <param name="strings">The strings to pack.</param>
        public UnmanagedArrayOfStrings(IList<string> strings)
        {
            if (strings != null)
            {
                var length = strings.Count;
                _unmanagedStrings = new IntPtr[length];
                var neededSize = length * IntPtr.Size;
                ArrayPtr = Marshal.AllocCoTaskMem(neededSize);
                for (var cx = length - 1; cx >= 0; cx--)
                {
                    _unmanagedStrings[cx] = Marshal.StringToCoTaskMemUni(strings[cx]);
                    Marshal.WriteIntPtr(ArrayPtr, cx * IntPtr.Size, _unmanagedStrings[cx]);
                }
            }
        }

        /// <summary>Gets the pointer to the packed array memory.</summary>
        public IntPtr ArrayPtr { get; private set; }

        /// <summary>Releases unmanaged and - optionally - managed resources.</summary>
        public void Dispose()
        {
            if (ArrayPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(ArrayPtr);
                ArrayPtr = IntPtr.Zero;
            }

            foreach (var ptr in _unmanagedStrings)
            {
                Marshal.FreeCoTaskMem(ptr);
            }
        }
    }

    /// <summary>Represents a common dialog that allows a user to select directory objects.</summary>
	/// <remarks>
	/// <para>
	/// The directory object picker dialog box enables a user to select one or more objects from either the global catalog, a Microsoft
	/// Windows 2000 domain or computer, a Microsoft Windows NT 4.0 domain or computer, or a workgroup. The object types from which a user
	/// can select include user, contact, group, and computer objects.
	/// </para>
	/// <para>This managed class wraps the Directory Object Picker common dialog from the Active Directory UI.</para>
	/// <para>
	/// It simplifies the scope (Locations) and filter (ObjectTypes) selection by allowing a single filter to be specified which applies to
	/// all scopes (translating to both up-level and down-level filter flags as necessary).
	/// </para>
	/// <para>
	/// The object type filter is also simplified by combining different types of groups (local, global, etc) and not using individual well
	/// known types in down-level scopes (only all well known types can be specified).
	/// </para>
	/// <para>
	/// The scope location is also simplified by combining down-level and up-level variations into a single locations flag, e.g. external domains.
	/// </para>
	/// </remarks>
	[DefaultProperty(nameof(DefaultObjectTypes))]
    public class DirectoryObjectPickerDialog : CommonDialog
    {
        /// <summary>The object picker dialog box.</summary>
        [ComImport, Guid("17D6CCD8-3B7B-11D2-B9E0-00C04FD8DBF7")]
        internal class DSObjectPicker
        {
        }

        /// <summary>Directory name types for use with IADsNameTranslate</summary>
        internal enum ADS_NAME_TYPE_ENUM
        {
            ADS_NAME_TYPE_1779 = 1,
            ADS_NAME_TYPE_CANONICAL = 2,
            ADS_NAME_TYPE_NT4 = 3,
            ADS_NAME_TYPE_DISPLAY = 4,
            ADS_NAME_TYPE_DOMAIN_SIMPLE = 5,
            ADS_NAME_TYPE_ENTERPRISE_SIMPLE = 6,
            ADS_NAME_TYPE_GUID = 7,
            ADS_NAME_TYPE_UNKNOWN = 8,
            ADS_NAME_TYPE_USER_PRINCIPAL_NAME = 9,
            ADS_NAME_TYPE_CANONICAL_EX = 10,
            ADS_NAME_TYPE_SERVICE_PRINCIPAL_NAME = 11,
            ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME = 12,
        }

        /// <summary>The DVASPECT enumeration values specify the desired data or view aspect of the object when drawing or getting data.</summary>
        internal enum DVASPECT
        {
            DVASPECT_CONTENT = 1,
            DVASPECT_THUMBNAIL = 2,
            DVASPECT_ICON = 4,
            DVASPECT_DOCPRINT = 8
        }

        /// <summary>The TYMED enumeration values indicate the type of storage medium being used in a data transfer.</summary>
        internal enum TYMED
        {
            TYMED_HGLOBAL = 1,
            TYMED_FILE = 2,
            TYMED_ISTREAM = 4,
            TYMED_ISTORAGE = 8,
            TYMED_GDI = 16,
            TYMED_MFPICT = 32,
            TYMED_ENHMF = 64,
            TYMED_NULL = 0
        }



        /// <summary>The CFSTR_DSOP_DS_SELECTION_LIST clipboard format is provided by the IDataObject obtained by calling IDsObjectPicker.InvokeDialog</summary>
        internal class CLIPBOARD_FORMAT
        {
            public const string CFSTR_DSOP_DS_SELECTION_LIST =
                "CFSTR_DSOP_DS_SELECTION_LIST";
        }

        /// <summary>
        /// The DS_SELECTION structure contains data about an object the user selected from an object picker dialog box. The DS_SELECTION_LIST
        /// structure contains an array of DS_SELECTION structures.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct DS_SELECTION
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwzName;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwzADsPath;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwzClass;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwzUPN;

            public IntPtr pvarFetchedAttributes;
            public uint flScopeType;
        }

        /// <summary>
        /// The DS_SELECTION_LIST structure contains data about the objects the user selected from an object picker dialog box. This structure
        /// is supplied by the IDataObject interface supplied by the IDsObjectPicker::InvokeDialog method in the CFSTR_DSOP_DS_SELECTION_LIST
        /// data format.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct DS_SELECTION_LIST
        {
            public uint cItems;
            public uint cFetchedAttributes;
            public DS_SELECTION[] aDsSelection;
        }

        /// <summary>
        /// The DSOP_FILTER_FLAGS structure contains flags that indicate the types of objects presented to the user for a specified scope or scopes.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct DSOP_FILTER_FLAGS
        {
            public DSOP_UPLEVEL_FILTER_FLAGS Uplevel;
            public uint flDownlevel;
        }

        /// <summary>The DSOP_INIT_INFO structure contains data required to initialize an object picker dialog box.</summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct DSOP_INIT_INFO
        {
            public uint cbSize;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwzTargetComputer;

            public uint cDsScopeInfos;
            public IntPtr aDsScopeInfos;
            public uint flOptions;
            public uint cAttributesToFetch;
            public IntPtr apwzAttributeNames;
        }

        /// <summary>
        /// The DSOP_SCOPE_INIT_INFO structure describes one or more scope types that have the same attributes. A scope type is a type of
        /// location, for example a domain, computer, or Global Catalog, from which the user can select objects.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto), Serializable]
        internal struct DSOP_SCOPE_INIT_INFO
        {
            public uint cbSize;
            public uint flType;
            public uint flScope;
            public DSOP_FILTER_FLAGS FilterFlags;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwzDcName;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pwzADsPath;

            public uint hr;
        }

        /// <summary>
        /// The DSOP_UPLEVEL_FILTER_FLAGS structure contains flags that indicate the filters to use for an up-level scope. An up-level scope is
        /// a scope that supports the ADSI LDAP provider.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct DSOP_UPLEVEL_FILTER_FLAGS
        {
            public uint flBothModes;
            public uint flMixedModeOnly;
            public uint flNativeModeOnly;
        }

        /// <summary>The IDsObjectPicker.InvokeDialog result</summary>
        internal enum HRESULT : int
        {
            E_NOTIMPL = unchecked((int)0x80004001),
            S_FALSE = 1, // The user cancelled the dialog box. ppdoSelections receives NULL.
            S_OK = 0, // The method succeeded
        }

        /// <summary>The IDsObjectPicker interface is used by an application to initialize and display an object picker dialog box.</summary>
        [ComImport, Guid("0C87E64E-3B7A-11D2-B9E0-00C04FD8DBF7"),
        InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IDsObjectPicker
        {
            [PreserveSig]
            HRESULT Initialize(ref DSOP_INIT_INFO pInitInfo);

            [PreserveSig]
            HRESULT InvokeDialog(IntPtr HWND, out IDataObject lpDataObject);
        }

        [ComImport, Guid("e2d3ec9b-d041-445a-8f16-4748de8fb1cf"),
         InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        internal interface IDsObjectPickerCredentials
        {
            [PreserveSig]
            int Initialize(ref DSOP_INIT_INFO pInitInfo);

            [PreserveSig]
            int InvokeDialog(IntPtr HWND, out IDataObject lpDataObject);

            [PreserveSig]
            int SetCredentials(string userName, string password);
        }

        /// <summary>This structure is used as a parameter in OLE functions and methods that require data format information.</summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct FORMATETC
        {
            public int cfFormat;
            public IntPtr ptd;
            public uint dwAspect;
            public int lindex;
            public uint tymed;
        }

        /// <summary>The STGMEDIUM structure is a generalized global memory handle used for data transfer operations by the IDataObject</summary>
        [StructLayout(LayoutKind.Sequential)]
        internal struct STGMEDIUM
        {
            public uint tymed;
            public IntPtr hGlobal;
            /* Presumably this is supposed to be an Object but according to a comment by xC0000005 on the
             * DSOP_INIT_INFO MSDN page, there is a bug in Windows whereby the returned object doesn't
             * support IUnknown, causing a E_NOT_IMPL error from .NET.
             *
             * Changing it to IntPtr makes it opaque to .NET and prevents the error
             */
            public IntPtr pUnkForRelease;
        }

        /// <summary>Frees the specified storage medium.</summary>
        /// <param name="pmedium">Pointer to the storage medium that is to be freed.</param>
        [DllImport("ole32")]
        internal static extern void ReleaseStgMedium([In] ref STGMEDIUM pmedium);

        /// <summary>Interface to enable data transfers</summary>
        [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
        Guid("0000010e-0000-0000-C000-000000000046")]
        internal interface IDataObject
        {
            [PreserveSig]
            HRESULT GetData(ref FORMATETC pFormatEtc, ref STGMEDIUM b);

            void GetDataHere(ref FORMATETC pFormatEtc, ref STGMEDIUM b);

            [PreserveSig]
            int QueryGetData(IntPtr a);

            [PreserveSig]
            int GetCanonicalFormatEtc(IntPtr a, IntPtr b);

            [PreserveSig]
            int SetData(IntPtr a, IntPtr b, int c);

            [PreserveSig]
            int EnumFormatEtc(uint a, IntPtr b);

            [PreserveSig]
            int DAdvise(IntPtr a, uint b, IntPtr c, ref uint d);

            [PreserveSig]
            int DUnadvise(uint a);

            [PreserveSig]
            int EnumDAdvise(IntPtr a);
        }

        [ComImport, Guid("9068270b-0939-11d1-8be1-00c04fd8d503")]
        internal interface IAdsLargeInteger
        {
            long HighPart { get; set; }
            long LowPart { get; set; }
        }

        [ComImport, Guid("274fae1f-3626-11d1-a3a4-00c04fb950dc")]
        internal class NameTranslate
        {
        }

        [Guid("B1B272A3-3625-11D1-A3A4-00C04FB950DC"),
#pragma warning disable CS0618 // Type or member is obsolete
        InterfaceType(ComInterfaceType.InterfaceIsIDispatch)]
#pragma warning restore CS0618 // Type or member is obsolete
        internal interface IADsNameTranslate
        {
            [DispId(1)]
            int ChaseReferral { set; }

            [DispId(5)]
            string Get(int lnFormatType);

            [DispId(7)]
            object GetEx(int lnFormatType);

            [DispId(2)]
            void Init(int lnSetType, string bstrADsPath);

            [DispId(3)]
            void InitEx(int lnSetType, string bstrADsPath, string bstrUserID, string bstrDomain, string bstrPassword);

            [DispId(4)]
            void Set(int lnSetType, string bstrADsPath);

            [DispId(6)]
            void SetEx(int lnFormatType, object pVar);
        }

        private DirectoryObject[] selectedObjects;
        private string userName, password;

        /// <summary>Constructor. Sets all properties to their default values.</summary>
        /// <remarks>
        /// <para>The default values for the DirectoryObjectPickerDialog properties are:</para>
        /// <para>
        /// <list type="table">
        /// <listheader>
        /// <term>Property</term>
        /// <description>Default value</description>
        /// </listheader>
        /// <item>
        /// <term>AllowedLocations</term>
        /// <description>All locations.</description>
        /// </item>
        /// <item>
        /// <term>AllowedObjectTypes</term>
        /// <description>All object types.</description>
        /// </item>
        /// <item>
        /// <term>DefaultLocations</term>
        /// <description>None. (Will default to first location.)</description>
        /// </item>
        /// <item>
        /// <term>DefaultObjectTypes</term>
        /// <description>All object types.</description>
        /// </item>
        /// <item>
        /// <term>Providers</term>
        /// <description><see cref="ADsPathsProviders.Default"/>.</description>
        /// </item>
        /// <item>
        /// <term>MultiSelect</term>
        /// <description>false.</description>
        /// </item>
        /// <item>
        /// <term>SkipDomainControllerCheck</term>
        /// <description>false.</description>
        /// </item>
        /// <item>
        /// <term>AttributesToFetch</term>
        /// <description>Empty list.</description>
        /// </item>
        /// <item>
        /// <term>SelectedObject</term>
        /// <description>null.</description>
        /// </item>
        /// <item>
        /// <term>SelectedObjects</term>
        /// <description>Empty array.</description>
        /// </item>
        /// <item>
        /// <term>ShowAdvancedView</term>
        /// <description>false.</description>
        /// </item>
        /// <item>
        /// <term>TargetComputer</term>
        /// <description>null.</description>
        /// </item>
        /// </list>
        /// </para>
        /// </remarks>
        public DirectoryObjectPickerDialog() => ResetInner();

        /// <summary>Gets or sets the scopes the DirectoryObjectPickerDialog is allowed to search.</summary>
        [Category("Behavior"), DefaultValue(typeof(Locations), "All"), Description("The scopes the dialog is allowed to search.")]
        public Locations AllowedLocations { get; set; }

        /// <summary>Gets or sets the types of objects the DirectoryObjectPickerDialog is allowed to search for.</summary>
        [Category("Behavior"), DefaultValue(typeof(ObjectTypes), "All"), Description("The types of objects the dialog is allowed to search for.")]
        public ObjectTypes AllowedObjectTypes { get; set; }

        /// <summary>A list of LDAP attribute names that will be retrieved for picked objects.</summary>
        [Category("Behavior"), Description("A list of LDAP attribute names that will be retrieved for picked objects.")]
        [DesignerSerializationVisibility(DesignerSerializationVisibility.Content)]
        public Collection<string> AttributesToFetch { get; set; }

        /// <summary>Gets or sets the initially selected scope in the DirectoryObjectPickerDialog.</summary>
        [Category("Behavior"), DefaultValue(typeof(Locations), "None"), Description("The initially selected scope in the dialog.")]
        public Locations DefaultLocations { get; set; }

        /// <summary>Gets or sets the initially seleted types of objects in the DirectoryObjectPickerDialog.</summary>
        [Category("Behavior"), DefaultValue(typeof(ObjectTypes), "All"), Description("The initially selected types of objects in the dialog.")]
        public ObjectTypes DefaultObjectTypes { get; set; }

        /// <summary>Gets or sets whether the user can select multiple objects.</summary>
        /// <remarks>
        /// <para>If this flag is false, the user can select only one object.</para>
        /// </remarks>
        [Category("Behavior"), DefaultValue(false), Description("Whether the user can select multiple objects.")]
        public bool MultiSelect { get; set; }

        /// <summary>Gets or sets the providers affecting the ADPath returned in objects.</summary>
        [Category("Behavior"), DefaultValue(typeof(ADsPathsProviders), "Default"), Description("The providers affecting the ADPath returned in objects.")]
        public ADsPathsProviders Providers { get; set; }

        /// <summary>Gets the directory object selected in the dialog, or null if no object was selected.</summary>
        /// <remarks>
        /// <para>
        /// If MultiSelect is enabled, then this property returns only the first selected object. Use SelectedObjects to get an array of all
        /// objects selected.
        /// </para>
        /// </remarks>
        [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        public DirectoryObject SelectedObject => selectedObjects == null || selectedObjects.Length == 0 ? null : selectedObjects[0];

        /// <summary>Gets an array of the directory objects selected in the dialog.</summary>
        [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
        public DirectoryObject[] SelectedObjects => selectedObjects == null ? (new DirectoryObject[0]) : (DirectoryObject[])selectedObjects.Clone();

        /// <summary>Gets or sets whether objects flagged as show in advanced view only are displayed (up-level).</summary>
        [Category("Appearance"), DefaultValue(false), Description("Whether objects flagged as show in advanced view only are displayed (up-level).")]
        public bool ShowAdvancedView { get; set; }

        /// <summary>Gets or sets the whether to check whether the target is a Domain Controller and hide the "Local Computer" scope</summary>
        /// <remarks>
        /// <para>
        /// From MSDN:
        ///
        /// If this flag is NOT set, then the DSOP_SCOPE_TYPE_TARGET_COMPUTER flag will be ignored if the target computer is a DC. This flag
        /// has no effect unless DSOP_SCOPE_TYPE_TARGET_COMPUTER is specified.
        /// </para>
        /// </remarks>
        [Category("Behavior"), DefaultValue(false), Description("Whether to check whether the target is a Domain Controller and hide the 'Local Computer' scope.")]
        public bool SkipDomainControllerCheck { get; set; }

        /// <summary>Gets or sets the name of the target computer.</summary>
        /// <remarks>
        /// <para>
        /// The dialog box operates as if it is running on the target computer, using the target computer to determine the joined domain and
        /// enterprise. If this value is null or empty, the target computer is the local computer.
        /// </para>
        /// </remarks>
        [Category("Behavior"), DefaultValue(null), Description("The name of the target computer.")]
        public string TargetComputer { get; set; }

        /// <summary>Resets all properties to their default values.</summary>
        public override void Reset() => ResetInner();

        /// <summary>Use this method to override the user credentials, passing new credentials for the account profile to be used.</summary>
        /// <param name="userName">Name of the user.</param>
        /// <param name="password">The password for the user.</param>
        public void SetCredentials(string userName, string password)
        {
            this.userName = userName;
            this.password = password;
        }

        /// <summary>Displays the Directory Object Picker (Active Directory) common dialog, when called by ShowDialog.</summary>
        /// <param name="hwndOwner">Handle to the window that owns the dialog.</param>
        /// <returns>
        /// If the user clicks the OK button of the Directory Object Picker dialog that is displayed, true is returned; otherwise, false.
        /// </returns>
        protected override bool RunDialog(IntPtr hwndOwner)
        {
            var ipicker = Initialize();
            if (ipicker == null)
            {
                selectedObjects = null;
                return false;
            }

            try
            {
                HRESULT hresult = ipicker.InvokeDialog(hwndOwner, out IDataObject dataObj);
                if (hresult == HRESULT.S_OK)
                {
                    selectedObjects = ProcessSelections(dataObj);
                    Marshal.ReleaseComObject(dataObj);
                    return true;
                }
                if (hresult == HRESULT.S_FALSE)
                {
                    selectedObjects = null;
                    return false;
                }
                throw new COMException("IDsObjectPicker.InvokeDialog failed", (int)hresult);
            }
            finally
            {
                Marshal.ReleaseComObject(ipicker);
            }
        }

        // Convert Locations to DSOP_SCOPE_TYPE_FLAGS
        private static DSOP_SCOPE_TYPE_FLAGS GetScope(Locations locations)
        {
            DSOP_SCOPE_TYPE_FLAGS scope = 0;
            if (locations.IsFlagSet(Locations.LocalComputer))
            {
                scope |= DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_TARGET_COMPUTER;
            }
            if (locations.IsFlagSet(Locations.JoinedDomain))
            {
                scope |= DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_DOWNLEVEL_JOINED_DOMAIN |
                        DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_UPLEVEL_JOINED_DOMAIN;
            }
            if (locations.IsFlagSet(Locations.EnterpriseDomain))
            {
                scope |= DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_ENTERPRISE_DOMAIN;
            }
            if (locations.IsFlagSet(Locations.GlobalCatalog))
            {
                scope |= DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_GLOBAL_CATALOG;
            }
            if (locations.IsFlagSet(Locations.ExternalDomain))
            {
                scope |= DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_EXTERNAL_DOWNLEVEL_DOMAIN |
                        DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_EXTERNAL_UPLEVEL_DOMAIN;
            }
            if (locations.IsFlagSet(Locations.Workgroup))
            {
                scope |= DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_WORKGROUP;
            }
            if (locations.IsFlagSet(Locations.UserEntered))
            {
                scope |= DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_USER_ENTERED_DOWNLEVEL_SCOPE |
                DSOP_SCOPE_TYPE_FLAGS.DSOP_SCOPE_TYPE_USER_ENTERED_UPLEVEL_SCOPE;
            }
            return scope;
        }

        // Convert ObjectTypes to DSCOPE_SCOPE_INIT_INFO_FLAGS
        private DSOP_SCOPE_INIT_INFO_FLAGS GetDefaultFilter()
        {
            DSOP_SCOPE_INIT_INFO_FLAGS defaultFilter = 0;
            if (DefaultObjectTypes.IsFlagSet(ObjectTypes.Users) || DefaultObjectTypes.IsFlagSet(ObjectTypes.WellKnownPrincipals))
            {
                defaultFilter |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_DEFAULT_FILTER_USERS;
            }
            if (DefaultObjectTypes.IsFlagSet(ObjectTypes.Groups) || DefaultObjectTypes.IsFlagSet(ObjectTypes.BuiltInGroups))
            {
                defaultFilter |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_DEFAULT_FILTER_GROUPS;
            }
            if (DefaultObjectTypes.IsFlagSet(ObjectTypes.Computers))
            {
                defaultFilter |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_DEFAULT_FILTER_COMPUTERS;
            }
            if (DefaultObjectTypes.IsFlagSet(ObjectTypes.Contacts))
            {
                defaultFilter |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_DEFAULT_FILTER_CONTACTS;
            }
            if (DefaultObjectTypes.IsFlagSet(ObjectTypes.ServiceAccounts))
            {
                defaultFilter |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_DEFAULT_FILTER_SERVICE_ACCOUNTS;
            }
            return defaultFilter;
        }

        // Convert ObjectTypes to DSOP_DOWNLEVEL_FLAGS
        private DSOP_DOWNLEVEL_FLAGS GetDownLevelFilter()
        {
            DSOP_DOWNLEVEL_FLAGS downlevelFilter = 0;
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.Users))
            {
                downlevelFilter |= DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_USERS;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.Groups))
            {
                downlevelFilter |= DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_LOCAL_GROUPS |
                                    DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_GLOBAL_GROUPS;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.Computers))
            {
                downlevelFilter |= DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_COMPUTERS;
            }
            // Contacts not available in downlevel scopes
            //if ((allowedTypes & ObjectTypes.Contacts) == ObjectTypes.Contacts)
            // Exclude build in groups if not selected
            if ((AllowedObjectTypes & ObjectTypes.BuiltInGroups) == 0)
            {
                downlevelFilter |= DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_EXCLUDE_BUILTIN_GROUPS;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.WellKnownPrincipals))
            {
                downlevelFilter |= DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_ALL_WELLKNOWN_SIDS;
                // This includes all the following:
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_WORLD |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_AUTHENTICATED_USER |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_ANONYMOUS |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_BATCH |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_CREATOR_OWNER |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_CREATOR_GROUP |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_DIALUP |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_INTERACTIVE |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_NETWORK |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_SERVICE |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_SYSTEM |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_TERMINAL_SERVER |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_LOCAL_SERVICE |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_NETWORK_SERVICE |
                //DSOP_DOWNLEVEL_FLAGS.DSOP_DOWNLEVEL_FILTER_REMOTE_LOGON;
            }
            return downlevelFilter;
        }

        private object[] GetFetchedAttributes(IntPtr pvarFetchedAttributes, int cFetchedAttributes, string schemaClassName)
        {
            var fetchedAttributes = cFetchedAttributes > 0 ? Marshal.GetObjectsForNativeVariants(pvarFetchedAttributes, cFetchedAttributes) : (new object[0]);
            for (var i = 0; i < fetchedAttributes.Length; i++)
            {
                if (fetchedAttributes[i] is IAdsLargeInteger largeInteger)
                {
                    var l = largeInteger.HighPart * 0x100000000L + (uint)largeInteger.LowPart;
                    fetchedAttributes[i] = l;
                }

                if (AttributesToFetch[i].Equals("objectClass", StringComparison.OrdinalIgnoreCase)) // see comments in Initialize() function
                    fetchedAttributes[i] = schemaClassName;
            }

            return fetchedAttributes;
        }

        // Convert ADsPathsProviders to DSOP_SCOPE_INIT_INFO_FLAGS
        private DSOP_SCOPE_INIT_INFO_FLAGS GetProviderFlags()
        {
            DSOP_SCOPE_INIT_INFO_FLAGS scope = 0;
            if (Providers.IsFlagSet(ADsPathsProviders.WinNT))
                scope |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_WANT_PROVIDER_WINNT;

            if (Providers.IsFlagSet(ADsPathsProviders.LDAP))
                scope |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_WANT_PROVIDER_LDAP;

            if (Providers.IsFlagSet(ADsPathsProviders.GC))
                scope |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_WANT_PROVIDER_GC;

            if (Providers.IsFlagSet(ADsPathsProviders.SIDPath))
                scope |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_WANT_SID_PATH;

            if (Providers.IsFlagSet(ADsPathsProviders.DownlevelBuiltinPath))
                scope |= DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_WANT_DOWNLEVEL_BUILTIN_PATH;

            return scope;
        }

        // Convert ObjectTypes to DSOP_FILTER_FLAGS_FLAGS
        private DSOP_FILTER_FLAGS_FLAGS GetUpLevelFilter()
        {
            DSOP_FILTER_FLAGS_FLAGS uplevelFilter = 0;
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.Users))
            {
                uplevelFilter |= DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_USERS;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.Groups))
            {
                uplevelFilter |= DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_UNIVERSAL_GROUPS_DL |
                                DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_UNIVERSAL_GROUPS_SE |
                                DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_GLOBAL_GROUPS_DL |
                                DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_GLOBAL_GROUPS_SE |
                                DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_DOMAIN_LOCAL_GROUPS_DL |
                                DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_DOMAIN_LOCAL_GROUPS_SE;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.Computers))
            {
                uplevelFilter |= DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_COMPUTERS;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.Contacts))
            {
                uplevelFilter |= DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_CONTACTS;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.BuiltInGroups))
            {
                uplevelFilter |= DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_BUILTIN_GROUPS;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.WellKnownPrincipals))
            {
                uplevelFilter |= DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_WELL_KNOWN_PRINCIPALS;
            }
            if (AllowedObjectTypes.IsFlagSet(ObjectTypes.ServiceAccounts))
            {
                uplevelFilter |= DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_SERVICE_ACCOUNTS;
            }
            if (ShowAdvancedView)
            {
                uplevelFilter |= DSOP_FILTER_FLAGS_FLAGS.DSOP_FILTER_INCLUDE_ADVANCED_VIEW;
            }
            return uplevelFilter;
        }

        private IDsObjectPicker Initialize()
        {
            DSObjectPicker picker = new DSObjectPicker();
            IDsObjectPicker ipicker = (IDsObjectPicker)picker;

            List<DSOP_SCOPE_INIT_INFO> scopeInitInfoList = new List<DSOP_SCOPE_INIT_INFO>();

            // Note the same default and filters are used by all scopes
            DSOP_SCOPE_INIT_INFO_FLAGS defaultFilter = GetDefaultFilter();
            var upLevelFilter = GetUpLevelFilter();
            var downLevelFilter = GetDownLevelFilter();
            var providerFlags = GetProviderFlags();

            // Internall, use one scope for the default (starting) locations.
            var startingScope = GetScope(DefaultLocations);
            if (startingScope > 0)
            {
                DSOP_SCOPE_INIT_INFO startingScopeInfo = new DSOP_SCOPE_INIT_INFO
                {
                    cbSize = (uint)Marshal.SizeOf(typeof(DSOP_SCOPE_INIT_INFO)),
                    flType = (uint)startingScope,
                    flScope = (uint)(DSOP_SCOPE_INIT_INFO_FLAGS.DSOP_SCOPE_FLAG_STARTING_SCOPE | defaultFilter | providerFlags),
                    pwzADsPath = null,
                    pwzDcName = null,
                    hr = 0,
                };
                startingScopeInfo.FilterFlags.Uplevel.flBothModes = (uint)upLevelFilter;
                startingScopeInfo.FilterFlags.flDownlevel = (uint)downLevelFilter;
                scopeInitInfoList.Add(startingScopeInfo);
            }

            // And another scope for all other locations (AllowedLocation values not in DefaultLocation)
            var otherLocations = AllowedLocations & (~DefaultLocations);
            var otherScope = GetScope(otherLocations);
            if (otherScope > 0)
            {
                var otherScopeInfo = new DSOP_SCOPE_INIT_INFO
                {
                    cbSize = (uint)Marshal.SizeOf(typeof(DSOP_SCOPE_INIT_INFO)),
                    flType = (uint)otherScope,
                    flScope = (uint)(defaultFilter | providerFlags),
                    pwzADsPath = null,
                    pwzDcName = null,
                    hr = 0
                };
                otherScopeInfo.FilterFlags.Uplevel.flBothModes = (uint)upLevelFilter;
                otherScopeInfo.FilterFlags.flDownlevel = (uint)downLevelFilter;
                scopeInitInfoList.Add(otherScopeInfo);
            }

            var scopeInitInfo = scopeInitInfoList.ToArray();

            // TODO: Scopes for alternate ADs, alternate domains, alternate computers, etc

            // Allocate memory from the unmananged mem of the process, this should be freed later!??
            var refScopeInitInfo = Marshal.AllocHGlobal
                (Marshal.SizeOf(typeof(DSOP_SCOPE_INIT_INFO)) * scopeInitInfo.Length);

            // Marshal structs to pointers
            for (var index = 0; index < scopeInitInfo.Length; index++)
            {
                Marshal.StructureToPtr(scopeInitInfo[index],
                                       refScopeInitInfo.OffsetWith(index * Marshal.SizeOf(typeof(DSOP_SCOPE_INIT_INFO))),
                                       false);
            }

            // Initialize structure with data to initialize an object picker dialog box.
            var initInfo = new DSOP_INIT_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(DSOP_INIT_INFO)),
                pwzTargetComputer = TargetComputer,
                cDsScopeInfos = (uint)scopeInitInfo.Length,
                aDsScopeInfos = refScopeInitInfo,
            };
            // Flags that determine the object picker options.
            DSOP_INIT_INFO_FLAGS flOptions = 0;
            if (MultiSelect)
            {
                flOptions |= DSOP_INIT_INFO_FLAGS.DSOP_FLAG_MULTISELECT;
            }
            // Only set DSOP_INIT_INFO_FLAGS.DSOP_FLAG_SKIP_TARGET_COMPUTER_DC_CHECK if we know target is not a DC (which then saves
            // initialization time).
            if (SkipDomainControllerCheck)
            {
                flOptions |= DSOP_INIT_INFO_FLAGS.DSOP_FLAG_SKIP_TARGET_COMPUTER_DC_CHECK;
            }
            initInfo.flOptions = (uint)flOptions;

            // there's a (seeming?) bug on my Windows XP when fetching the objectClass attribute - the pwzClass field is corrupted... plus,
            // it returns a multivalued array for this attribute. In Windows 2008 R2, however, only last value is returned, just as in
            // pwzClass. So won't actually be retrieving __objectClass__ - will give pwzClass instead
            var goingToFetch = new List<string>(AttributesToFetch);
            for (var i = 0; i < goingToFetch.Count; i++)
            {
                if (goingToFetch[i].Equals("objectClass", StringComparison.OrdinalIgnoreCase))
                    goingToFetch[i] = "__objectClass__";
            }

            initInfo.cAttributesToFetch = (uint)goingToFetch.Count;
            var unmanagedAttributesToFetch = new UnmanagedArrayOfStrings(goingToFetch);
            initInfo.apwzAttributeNames = unmanagedAttributesToFetch.ArrayPtr;

            // If the user has defined new credentials, set them now
            if (!string.IsNullOrEmpty(userName))
            {
                var cred = (IDsObjectPickerCredentials)ipicker;
                cred.SetCredentials(userName, password);
            }

            try
            {
                // Initialize the Object Picker Dialog Box with our options
                var hresult = ipicker.Initialize(ref initInfo);
                if (hresult != HRESULT.S_OK)
                {
                    Marshal.ReleaseComObject(ipicker);
                    throw new COMException("IDsObjectPicker.Initialize failed", (int)hresult);
                }
                return ipicker;
            }
            finally
            {
                /*
				 from MSDN (http://msdn.microsoft.com/en-us/library/ms675899(VS.85).aspx):

					 Initialize can be called multiple times, but only the last call has effect.
					 Be aware that object picker makes its own copy of InitInfo.
				 */
                Marshal.FreeHGlobal(refScopeInitInfo);
                unmanagedAttributesToFetch.Dispose();
            }
        }

        private DirectoryObject[] ProcessSelections(IDataObject dataObj)
        {
            if (dataObj == null)
                return null;

            DirectoryObject[] selections = null;

            // The STGMEDIUM structure is a generalized global memory handle used for data transfer operations
            STGMEDIUM stg = new STGMEDIUM
            {
                tymed = (uint)TYMED.TYMED_HGLOBAL,
                hGlobal = IntPtr.Zero,
                pUnkForRelease = IntPtr.Zero
            };

            // The FORMATETC structure is a generalized Clipboard format.
            var fe = new FORMATETC
            {
                cfFormat = DataFormats.GetFormat(CLIPBOARD_FORMAT.CFSTR_DSOP_DS_SELECTION_LIST).Id,
                // The CFSTR_DSOP_DS_SELECTION_LIST clipboard format is provided by the IDataObject obtained by calling IDsObjectPicker::InvokeDialog
                ptd = IntPtr.Zero,
                dwAspect = 1, //DVASPECT.DVASPECT_CONTENT    = 1,
                lindex = -1, // all of the data
                tymed = (uint)TYMED.TYMED_HGLOBAL //The storage medium is a global memory handle (HGLOBAL)
            };

            HRESULT hresult = dataObj.GetData(ref fe, ref stg);
            if (hresult != HRESULT.S_OK) throw new COMException("IDataObject.GetData failed", (int)hresult);

            var pDsSL = Windows.GlobalLock(stg.hGlobal);
            if (pDsSL == IntPtr.Zero) throw new Win32Exception("GlobalLock(stg.hGlobal) failed");

            try
            {
                // the start of our structure
                var current = pDsSL;
                // get the # of items selected
                int cnt = Marshal.ReadInt32(current);
                int cFetchedAttributes = Marshal.ReadInt32(current, Marshal.SizeOf(typeof(uint)));

                // if we selected at least 1 object
                if (cnt > 0)
                {
                    selections = new DirectoryObject[cnt];
                    // increment the pointer so we can read the DS_SELECTION structure
                    current = current.OffsetWith(Marshal.SizeOf(typeof(uint)) * 2);
                    // now loop through the structures
                    for (var i = 0; i < cnt; i++)
                    {
                        // marshal the pointer to the structure
                        var s = (DS_SELECTION)Marshal.PtrToStructure(current, typeof(DS_SELECTION));

                        // increment the position of our pointer by the size of the structure
                        current = current.OffsetWith(Marshal.SizeOf(typeof(DS_SELECTION)));

                        var name = s.pwzName;
                        var path = s.pwzADsPath;
                        var schemaClassName = s.pwzClass;
                        var upn = s.pwzUPN;
                        var fetchedAttributes = GetFetchedAttributes(s.pvarFetchedAttributes, cFetchedAttributes, schemaClassName);

                        selections[i] = new DirectoryObject(name, path, schemaClassName, upn, fetchedAttributes);
                    }
                }
            }
            finally
            {
                Windows.GlobalUnlock(pDsSL);
                ReleaseStgMedium(ref stg);
            }
            return selections;
        }

#pragma warning disable IDE0051 // Remove unused private members
        private void ResetAttributesToFetch()
        {
            AttributesToFetch = new Collection<string>();
        }
#pragma warning restore IDE0051 // Remove unused private members

        private void ResetInner() // can be called from constructor without a "Virtual member call in constructor" warning
        {
            AllowedLocations = Locations.All;
            AllowedObjectTypes = ObjectTypes.All;
            DefaultLocations = Locations.None;
            DefaultObjectTypes = ObjectTypes.All;
            Providers = ADsPathsProviders.Default;
            MultiSelect = false;
            SkipDomainControllerCheck = false;
            ResetAttributesToFetch();
            selectedObjects = null;
            ShowAdvancedView = false;
            TargetComputer = null;
        }

        private bool ShouldSerializeAttributesToFetch() => AttributesToFetch != null && AttributesToFetch.Count > 0;
    }
}
